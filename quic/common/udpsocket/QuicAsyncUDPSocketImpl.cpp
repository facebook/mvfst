/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/udpsocket/QuicAsyncUDPSocketImpl.h>

namespace {
constexpr socklen_t kAddrLen = sizeof(sockaddr_storage);
} // namespace

namespace quic {

QuicAsyncUDPSocket::RecvResult QuicAsyncUDPSocketImpl::recvmmsgNetworkData(
    uint64_t readBufferSize,
    uint16_t numPackets,
    NetworkData& networkData,
    folly::Optional<folly::SocketAddress>& peerAddress,
    size_t& totalData) {
  /**
   * This is largely a copy / paste of QuicClientTransport::recvmmsg.
   *
   * TODO(bschlinker): Refactor and add dedicated testing.
   */
  recvmmsgStorage_.resize(numPackets);
  auto& msgs = recvmmsgStorage_.msgs;
  int flags = 0;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  bool useGRO = getGRO() > 0;
  bool checkCmsgs = useGRO || getTimestamping() > 0 || getRecvTos();
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
      readBuffer = folly::IOBuf::createCombined(readBufferSize);
      iovec.iov_base = readBuffer->writableData();
      iovec.iov_len = readBufferSize;
      msg->msg_iov = &iovec;
      msg->msg_iovlen = 1;
    }
    CHECK(readBuffer != nullptr);

    auto* rawAddr = reinterpret_cast<sockaddr*>(&addr);
    rawAddr->sa_family = address().getFamily();
    msg->msg_name = rawAddr;
    msg->msg_namelen = kAddrLen;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
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
    // a packet that we could process, however let's just quit early.
    pauseRead();
    return RecvResult(NoReadReason::NONRETRIABLE_ERROR);
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
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
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
      const auto timespecToTimestamp = [](const timespec& ts)
          -> folly::Optional<ReceivedUdpPacket::Timings::SocketTimestampExt> {
        std::chrono::nanoseconds duration = std::chrono::seconds(ts.tv_sec) +
            std::chrono::nanoseconds(ts.tv_nsec);
        if (duration == duration.zero()) {
          return folly::none;
        }

        ReceivedUdpPacket::Timings::SocketTimestampExt sockTsExt;
        sockTsExt.rawDuration = duration;
        sockTsExt.systemClock.raw = std::chrono::system_clock::time_point(
            std::chrono::duration_cast<std::chrono::system_clock::duration>(
                duration));
        return sockTsExt;
      };

      const auto& ts = *params.ts;
      timings.maybeSoftwareTs = timespecToTimestamp(ts[0]);
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

  return {};
}

void QuicAsyncUDPSocketImpl::RecvmmsgStorage::resize(size_t numPackets) {
  if (msgs.size() != numPackets) {
    msgs.resize(numPackets);
    impl_.resize(numPackets);
  }
}
} // namespace quic
