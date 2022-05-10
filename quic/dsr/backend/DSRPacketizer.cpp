/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/IoBufQuicBatch.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/dsr/backend/DSRPacketizer.h>

namespace quic {
bool writeSingleQuicPacket(
    IOBufQuicBatch& ioBufBatch,
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
  ShortHeader shortHeader(ProtectionType::KeyPhaseZero, dcid, packetNum);
  // The the stream length limit calculated by the frontend should have
  // already taken the PMTU limit into account. Thus the packet builder uses
  // uint32 max value as packet size limit.
  // TODO: InplaceQuicPacketBuilder in the future
  RegularQuicPacketBuilder builder(
      std::numeric_limits<uint32_t>::max() /* udpSendPacketLen */,
      std::move(shortHeader),
      largestAckedByPeer);
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
      true /* skip length field in stream header */);
  BufQueue bufQueue(std::move(buf));
  writeStreamFrameData(builder, bufQueue, *dataLen);
  auto packet = std::move(builder).buildPacket();

  if (packet.packet.frames.empty()) {
    LOG(ERROR) << "DSR Send failed: Build empty packet.";
    ioBufBatch.flush();
    return false;
  }
  if (!packet.body) {
    LOG(ERROR) << "DSR Send failed: Build empty body buffer";
    ioBufBatch.flush();
    return false;
  }
  packet.header->coalesce();
  auto headerLen = packet.header->length();
  auto bodyLen = packet.body->computeChainDataLength();
  auto unencrypted = folly::IOBuf::createCombined(
      headerLen + bodyLen + aead.getCipherOverhead());
  auto bodyCursor = folly::io::Cursor(packet.body.get());
  bodyCursor.pull(unencrypted->writableData() + headerLen, bodyLen);
  unencrypted->advance(headerLen);
  unencrypted->append(bodyLen);
  auto packetBuf = aead.inplaceEncrypt(
      std::move(unencrypted), packet.header.get(), packetNum);
  DCHECK(packetBuf->headroom() == headerLen);
  packetBuf->clear();
  auto headerCursor = folly::io::Cursor(packet.header.get());
  headerCursor.pull(packetBuf->writableData(), headerLen);
  packetBuf->append(headerLen + bodyLen + aead.getCipherOverhead());
  encryptPacketHeader(
      HeaderForm::Short,
      packetBuf->writableData(),
      headerLen,
      packetBuf->data() + headerLen,
      packetBuf->length() - headerLen,
      headerCipher);
  auto encodedSize = packetBuf->computeChainDataLength();
  bool ret = ioBufBatch.write(std::move(packetBuf), encodedSize);
  // If ret is false, IOBufQuicBatch::flush() inside the IOBufQuicBatch::write()
  // above has failed, no need to try flush() again.
  return ret;
}

BufQuicBatchResult writePacketsGroup(
    folly::AsyncUDPSocket& sock,
    RequestGroup& reqGroup,
    const std::function<Buf(const PacketizationRequest& req)>& bufProvider) {
  if (reqGroup.requests.empty()) {
    LOG(ERROR) << "Empty packetization request";
    return {};
  }
  // TODO: Why don't I just limit the batch size to reqGroup.size()? What can go
  //  wrong?
  auto batchWriter =
      BatchWriterPtr(new GSOPacketBatchWriter(kDefaultQuicMaxBatchSize));
  // This doesn't matter:
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
