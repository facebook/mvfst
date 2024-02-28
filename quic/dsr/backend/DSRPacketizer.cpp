/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/IoBufQuicBatch.h>
#include <quic/api/QuicGsoBatchWriters.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/dsr/backend/DSRPacketizer.h>

namespace quic {
bool PacketGroupWriter::writeSingleQuicPacket(
    BufAccessor& accessor,
    ConnectionId dcid,
    PacketNum packetNum,
    PacketNum largestAckedByPeer,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    StreamId streamId,
    size_t offset,
    size_t length,
    bool eof,
    Buf buf) {
  if (buf->computeChainDataLength() < length) {
    LOG(ERROR) << "Insufficient data buffer";
    return false;
  }
  auto buildBuf = accessor.obtain();
  prevSize_ = buildBuf->length();
  accessor.release(std::move(buildBuf));

  ShortHeader shortHeader(ProtectionType::KeyPhaseZero, dcid, packetNum);
  InplaceQuicPacketBuilder builder(
      accessor,
      kDefaultMaxUDPPayload,
      std::move(shortHeader),
      largestAckedByPeer,
      0);
  builder.encodePacketHeader();
  builder.accountForCipherOverhead(aead.getCipherOverhead());
  // frontend has already limited the length to flow control, thus
  // flowControlLen == length
  auto dataLen = writeStreamFrameHeader(
      builder,
      streamId,
      offset,
      length,
      length /* flow control len*/,
      eof,
      true /* skip length field in stream header */,
      folly::none, /* stream group id */
      false /* don't append frame to builder */);
  BufQueue bufQueue(std::move(buf));
  writeStreamFrameData(builder, bufQueue, *dataLen);
  auto packet = std::move(builder).buildPacket();
  CHECK(accessor.ownsBuffer());

  if (packet.packet.empty) {
    LOG(ERROR) << "DSR Send failed: Build empty packet.";
    rollback();
    flush();
    return false;
  }
  if (packet.body.empty()) {
    LOG(ERROR) << "DSR Send failed: Build empty body buffer";
    rollback();
    flush();
    return false;
  }
  CHECK(!packet.header.isChained());

  auto headerLen = packet.header.length();
  buildBuf = accessor.obtain();
  CHECK(
      packet.body.data() > buildBuf->data() &&
      packet.body.tail() <= buildBuf->tail());
  CHECK(
      packet.header.data() >= buildBuf->data() &&
      packet.header.tail() < buildBuf->tail());
  // Trim off everything before the current packet, and the header length, so
  // buildBuf's data starts from the body part of buildBuf.
  buildBuf->trimStart(prevSize_ + headerLen);
  // buildBuf and packetbuildBuf is actually the same.
  auto packetbuildBuf =
      aead.inplaceEncrypt(std::move(buildBuf), &packet.header, packetNum);
  CHECK_EQ(packetbuildBuf->headroom(), headerLen + prevSize_);
  // Include header back.
  packetbuildBuf->prepend(headerLen);

  HeaderForm headerForm = packet.packet.header.getHeaderForm();
  encryptPacketHeader(
      headerForm,
      packetbuildBuf->writableData(),
      headerLen,
      packetbuildBuf->data() + headerLen,
      packetbuildBuf->length() - headerLen,
      headerCipher);
  CHECK(!packetbuildBuf->isChained());
  auto encodedSize = packetbuildBuf->length();
  // Include previous packets back.
  packetbuildBuf->prepend(prevSize_);
  accessor.release(std::move(packetbuildBuf));
  bool ret = send(encodedSize);
  return ret;
}

BufQuicBatchResult PacketGroupWriter::writePacketsGroup(
    RequestGroup& reqGroup,
    const std::function<Buf(const PacketizationRequest& req)>& bufProvider) {
  if (reqGroup.requests.empty()) {
    LOG(ERROR) << "Empty packetization request";
    return {};
  }
  if (!reqGroup.cipherPair->aead || !reqGroup.cipherPair->headerCipher) {
    LOG(ERROR) << "Missing ciphers";
    return {};
  }
  // It's ok if reqGourp's size is larger than ioBufBatch's batch size. The
  // ioBufBatch will flush when it hits the limit then start a new batch
  // transparently.
  for (const auto& request : reqGroup.requests) {
    auto bufAccessor = getBufAccessor();
    if (!bufAccessor) {
      // We hit this path only when there are no free UMEM frames when we're
      // using AF_XDP.
      return getResult();
    }
    auto ret = writeSingleQuicPacket(
        *bufAccessor,
        reqGroup.dcid,
        request.packetNum,
        request.largestAckedPacketNum,
        *reqGroup.cipherPair->aead,
        *reqGroup.cipherPair->headerCipher,
        request.streamId,
        request.offset,
        request.len,
        request.fin,
        bufProvider(request));
    if (!ret) {
      return getResult();
    }
  }
  flush();
  return getResult();
}

static auto& getThreadLocalConn(size_t maxPackets = 44) {
  static thread_local QuicConnectionStateBase fakeConn{QuicNodeType::Server};
  static thread_local bool initAccessor [[maybe_unused]] = [&]() {
    fakeConn.bufAccessor =
        new SimpleBufAccessor{kDefaultMaxUDPPayload * maxPackets};
    // Store this so we can use it to set the batch writer.
    fakeConn.transportSettings.maxBatchSize = maxPackets;
    return true;
  }();
  return fakeConn;
}

UdpSocketPacketGroupWriter::UdpSocketPacketGroupWriter(
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& clientAddress,
    BatchWriterPtr&& batchWriter)
    : sock_(sock),
      fakeConn_(getThreadLocalConn()),
      ioBufBatch_(
          std::move(batchWriter),
          sock_,
          clientAddress,
          nullptr /* statsCallback */,
          nullptr /* happyEyeballsState */) {}

UdpSocketPacketGroupWriter::UdpSocketPacketGroupWriter(
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& clientAddress)
    : sock_(sock),
      fakeConn_(getThreadLocalConn()),
      ioBufBatch_(
          BatchWriterPtr(new GSOInplacePacketBatchWriter(
              fakeConn_,
              fakeConn_.transportSettings.maxBatchSize)),
          sock_,
          clientAddress,
          nullptr /* statsCallback */,
          nullptr /* happyEyeballsState */) {}

BufAccessor* UdpSocketPacketGroupWriter::getBufAccessor() {
  return fakeConn_.bufAccessor;
}

void UdpSocketPacketGroupWriter::rollback() {
  auto buildBuf = getBufAccessor()->obtain();
  buildBuf->trimEnd(buildBuf->length() - prevSize_);
  getBufAccessor()->release(std::move(buildBuf));
}

bool UdpSocketPacketGroupWriter::send(uint32_t size) {
  return ioBufBatch_.write(nullptr /* no need to pass buildBuf */, size);
}

void UdpSocketPacketGroupWriter::flush() {
  ioBufBatch_.flush();
}

BufQuicBatchResult UdpSocketPacketGroupWriter::getResult() {
  return ioBufBatch_.getResult();
}

#if defined(__linux__)

void XskPacketGroupWriter::flush() {
  // Leaving this blank because the XskContainer does some flushing internally
}

BufAccessor* XskPacketGroupWriter::getBufAccessor() {
  auto maybeXskBuffer =
      xskSender_->getXskBuffer(vipAddress_.getIPAddress().isV6());
  if (!maybeXskBuffer) {
    LOG(ERROR) << "Failed to get XskBuffer, no free UMEM frames";
    currentXskBuffer_.buffer = nullptr;
    currentXskBuffer_.payloadLength = 0;
    currentXskBuffer_.frameIndex = 0;
    return nullptr;
  }
  currentXskBuffer_ = *maybeXskBuffer;
  auto ioBuf = folly::IOBuf::takeOwnership(
      currentXskBuffer_.buffer,
      kDefaultMaxUDPPayload,
      0,
      [](void* /* buf */, void* /* userData */) {
        // Empty destructor because we don't own the buffer
      });
  bufAccessor_ = std::make_unique<SimpleBufAccessor>(std::move(ioBuf));
  return bufAccessor_.get();
}

void XskPacketGroupWriter::rollback() {
  xskSender_->returnBuffer(currentXskBuffer_);
}

bool XskPacketGroupWriter::send(uint32_t size) {
  currentXskBuffer_.payloadLength = size;
  xskSender_->writeXskBuffer(currentXskBuffer_, clientAddress_, vipAddress_);
  result_.bytesSent += size;
  result_.packetsSent++;
  return true;
}

BufQuicBatchResult XskPacketGroupWriter::getResult() {
  return result_;
}

#endif

} // namespace quic
