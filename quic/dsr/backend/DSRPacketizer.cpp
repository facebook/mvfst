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
bool writeSingleQuicPacket(
    IOBufQuicBatch& ioBufBatch,
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
  auto prevSize = buildBuf->length();
  accessor.release(std::move(buildBuf));

  auto rollbackBuf = [&accessor, prevSize]() {
    auto buildBuf = accessor.obtain();
    buildBuf->trimEnd(buildBuf->length() - prevSize);
    accessor.release(std::move(buildBuf));
  };

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
    ioBufBatch.flush();
    return false;
  }
  if (!packet.body) {
    LOG(ERROR) << "DSR Send failed: Build empty body buffer";
    rollbackBuf();
    ioBufBatch.flush();
    return false;
  }
  CHECK(!packet.header->isChained());

  auto headerLen = packet.header->length();
  buildBuf = accessor.obtain();
  CHECK(
      packet.body->data() > buildBuf->data() &&
      packet.body->tail() <= buildBuf->tail());
  CHECK(
      packet.header->data() >= buildBuf->data() &&
      packet.header->tail() < buildBuf->tail());
  // Trim off everything before the current packet, and the header length, so
  // buildBuf's data starts from the body part of buildBuf.
  buildBuf->trimStart(prevSize + headerLen);
  // buildBuf and packetbuildBuf is actually the same.
  auto packetbuildBuf =
      aead.inplaceEncrypt(std::move(buildBuf), packet.header.get(), packetNum);
  CHECK_EQ(packetbuildBuf->headroom(), headerLen + prevSize);
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
  packetbuildBuf->prepend(prevSize);
  accessor.release(std::move(packetbuildBuf));
  bool ret =
      ioBufBatch.write(nullptr /* no need to pass buildBuf */, encodedSize);
  return ret;
}

// TODO using a connection state for this is kind of janky and we should
// refactor the batch writer interface to not need this.
// This isn't a real connection, it's just used for the batch writer state.
// 44 is near the number of the maximum GSO the kernel can accept for a full
// Ethernet MTU (44 * 1452 = 63888)
static auto& getThreadLocalConn(size_t maxPackets = 44) {
  static thread_local QuicConnectionStateBase fakeConn{QuicNodeType::Server};
  static thread_local bool initAccessor FOLLY_MAYBE_UNUSED = [&]() {
    fakeConn.bufAccessor =
        new SimpleBufAccessor{kDefaultMaxUDPPayload * maxPackets};
    // Store this so we can use it to set the batch writer.
    fakeConn.transportSettings.maxBatchSize = maxPackets;
    return true;
  }();
  return fakeConn;
}

BufQuicBatchResult writePacketsGroup(
    QuicAsyncUDPSocketWrapper& sock,
    RequestGroup& reqGroup,
    const std::function<Buf(const PacketizationRequest& req)>& bufProvider) {
  if (reqGroup.requests.empty()) {
    LOG(ERROR) << "Empty packetization request";
    return {};
  }
  auto& fakeConn = getThreadLocalConn();
  auto& bufAccessor = *fakeConn.bufAccessor;
  auto batchWriter = BatchWriterPtr(new GSOInplacePacketBatchWriter(
      fakeConn, fakeConn.transportSettings.maxBatchSize));
  IOBufQuicBatch ioBufBatch(
      std::move(batchWriter),
      false /* thread local batching */,
      sock,
      reqGroup.clientAddress,
      nullptr /* statsCallback */,
      nullptr /* happyEyeballsState */);
  if (!reqGroup.cipherPair->aead || !reqGroup.cipherPair->headerCipher) {
    LOG(ERROR) << "Missing ciphers";
    return {};
  }
  // It's ok if reqGourp's size is larger than ioBufBatch's batch size. The
  // ioBufBatch will flush when it hits the limit then start a new batch
  // transparently.
  for (const auto& request : reqGroup.requests) {
    auto ret = writeSingleQuicPacket(
        ioBufBatch,
        bufAccessor,
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
      return ioBufBatch.getResult();
    }
  }
  ioBufBatch.flush();
  return ioBufBatch.getResult();
}

} // namespace quic
