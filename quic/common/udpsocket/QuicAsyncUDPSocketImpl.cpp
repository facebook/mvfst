/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Likely.h>
#include <quic/QuicException.h> // For QuicError, QuicErrorCode, TransportErrorCode
#include <quic/common/StringUtils.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocketImpl.h>

namespace {
constexpr socklen_t kAddrLen = sizeof(sockaddr_storage);
} // namespace

namespace quic {

quic::Expected<QuicAsyncUDPSocket::RecvResult, QuicError>
QuicAsyncUDPSocketImpl::recvmmsgNetworkData(
    uint64_t readBufferSize,
    uint16_t numPackets,
    NetworkData& networkData,
    Optional<folly::SocketAddress>& peerAddress,
    size_t& totalData) {
  /**
   * This is largely a copy / paste of QuicClientTransport::recvmmsg.
   *
   * TODO(bschlinker): Refactor and add dedicated testing.
   */
  recvmmsgStorage_.resize(numPackets);
  auto& msgs = recvmmsgStorage_.msgs;
  int flags = 0;

  // Check socket options using Expected results
  auto groResult = getGRO();
  if (FOLLY_UNLIKELY(groResult.hasError())) {
    return quic::make_unexpected(groResult.error());
  }
  auto timestampingResult = getTimestamping();
  if (FOLLY_UNLIKELY(timestampingResult.hasError())) {
    return quic::make_unexpected(timestampingResult.error());
  }
  auto recvTosResult = getRecvTos();
  if (FOLLY_UNLIKELY(recvTosResult.hasError())) {
    return quic::make_unexpected(recvTosResult.error());
  }
#if defined(FOLLY_HAVE_MSG_ERRQUEUE) || defined(_WIN32)
  bool useGRO = *groResult > 0;
  bool checkCmsgs = useGRO || *timestampingResult > 0 || *recvTosResult;
  std::vector<std::array<
      char,
      QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams::kCmsgSpace>>
      controlVec(checkCmsgs ? numPackets : 0);

  // we need to consider MSG_TRUNC too
  if (useGRO) {
    flags |= MSG_TRUNC;
  }
#endif
  for (uint16_t i = 0; i < numPackets; ++i) {
    auto& addr = recvmmsgStorage_.impl_[i].addr;
    auto& readBuffer = recvmmsgStorage_.impl_[i].readBuffer;
    auto& iovec = recvmmsgStorage_.impl_[i].iovec;
    struct msghdr* msg = &msgs[i].msg_hdr;

    if (!readBuffer) {
      readBuffer = BufHelpers::createCombined(readBufferSize);
      iovec.iov_base = readBuffer->writableData();
      iovec.iov_len = readBufferSize;
      msg->msg_iov = &iovec;
      msg->msg_iovlen = 1;
    }
    CHECK(readBuffer != nullptr);

    auto localAddrResult = address();
    if (FOLLY_UNLIKELY(localAddrResult.hasError())) {
      return quic::make_unexpected(localAddrResult.error());
    }
    auto* rawAddr =
        reinterpret_cast<sockaddr*>(&addr); // Assuming addr is large enough
    rawAddr->sa_family = localAddrResult->getFamily();
    msg->msg_name = rawAddr;
    msg->msg_namelen = kAddrLen;
#if defined(FOLLY_HAVE_MSG_ERRQUEUE) || defined(_WIN32)
    if (checkCmsgs) {
      ::memset(controlVec[i].data(), 0, controlVec[i].size());
      msg->msg_control = controlVec[i].data();
      msg->msg_controllen = controlVec[i].size();
    }
#endif
  }

  // recvmmsg
  int numMsgsRecvd = recvmmsg(msgs.data(), numPackets, flags, nullptr);
  if (numMsgsRecvd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // Exit, socket will notify us again when socket is readable.
      return RecvResult(NoReadReason::RETRIABLE_ERROR);
    }
    // If we got a non-retriable error, we might have received
    // a packet that we could process, however let's just quit early. Pause read
    // might fail too.
    pauseRead();
    // Return the error from recvmmsg itself
    int errnoCopy = errno;
    std::string errorMsg = "recvmmsg failed: " + quic::errnoStr(errnoCopy);
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
        std::move(errorMsg)));
    // Original code returned RecvResult(NoReadReason::NONRETRIABLE_ERROR);
    // Returning the actual error seems more informative.
  }

  // process msgs (packets) returned by recvmmsg
  CHECK_LE(numMsgsRecvd, numPackets);
  for (uint16_t i = 0; i < static_cast<uint16_t>(numMsgsRecvd); ++i) {
    auto& addr = recvmmsgStorage_.impl_[i].addr;
    auto& readBuffer = recvmmsgStorage_.impl_[i].readBuffer;
    auto& msg = msgs[i];

    size_t bytesRead = msg.msg_len;
    if (bytesRead == 0) {
      // Empty datagram, this is probably garbage matching our tuple, we
      // should ignore such datagrams.
      continue;
    }
    QuicAsyncUDPSocket::ReadCallback::OnDataAvailableParams params;
#if defined(FOLLY_HAVE_MSG_ERRQUEUE) || defined(_WIN32)
    if (checkCmsgs) {
      QuicAsyncUDPSocket::fromMsg(params, msg.msg_hdr);

      // truncated
      if (bytesRead > readBufferSize) {
        bytesRead = readBufferSize;
        if (params.gro > 0) {
          bytesRead = bytesRead - bytesRead % params.gro;
        }
      }
    }
#endif
    totalData += bytesRead;

    if (!peerAddress) {
      peerAddress.emplace(folly::SocketAddress());
      auto* rawAddr = reinterpret_cast<sockaddr*>(&addr);
      peerAddress->setFromSockaddr(rawAddr, kAddrLen);
    }

    // timings
    ReceivedUdpPacket::Timings timings;

    // socket timestamps
    //
    // ts[0] -> software timestamp
    // ts[1] -> hardware timestamp transformed to userspace time (deprecated)
    // ts[2] -> hardware timestamp
    if (params.ts.has_value()) {
      timings.maybeSoftwareTs = convertToSocketTimestampExt(*params.ts);
    }

    VLOG(10) << "Got data from socket peer=" << *peerAddress
             << " len=" << bytesRead;
    readBuffer->append(bytesRead);
    if (params.gro > 0) {
      size_t len = bytesRead;
      size_t remaining = len;
      size_t offset = 0;
      size_t totalNumPackets = networkData.getPackets().size() +
          ((len + params.gro - 1) / params.gro);
      networkData.reserve(totalNumPackets);
      while (remaining) {
        if (static_cast<int>(remaining) > params.gro) {
          auto tmp = readBuffer->cloneOne();
          // start at offset
          tmp->trimStart(offset);
          // the actual len is len - offset now
          // leave gro bytes
          tmp->trimEnd(len - offset - params.gro);
          DCHECK_EQ(tmp->length(), params.gro);

          offset += params.gro;
          remaining -= params.gro;
          networkData.addPacket(
              ReceivedUdpPacket(std::move(tmp), timings, params.tos));
        } else {
          // do not clone the last packet
          // start at offset, use all the remaining data
          readBuffer->trimStart(offset);
          DCHECK_EQ(readBuffer->length(), remaining);
          remaining = 0;
          networkData.addPacket(
              ReceivedUdpPacket(std::move(readBuffer), timings, params.tos));
        }
      }
    } else {
      networkData.addPacket(
          ReceivedUdpPacket(std::move(readBuffer), timings, params.tos));
    }
  }

  return RecvResult(); // Success case
}

void QuicAsyncUDPSocketImpl::RecvmmsgStorage::resize(size_t numPackets) {
  if (msgs.size() != numPackets) {
    msgs.resize(numPackets);
    impl_.resize(numPackets);
  }
}
} // namespace quic
