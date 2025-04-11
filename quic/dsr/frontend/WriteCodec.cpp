/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/Optional.h>
#include <quic/dsr/frontend/WriteCodec.h>

namespace quic {

folly::Expected<uint32_t, QuicError> writeDSRStreamFrame(
    DSRPacketBuilderBase& packetBuilder,
    SendInstruction::Builder& instructionBuilder,
    StreamId id,
    uint64_t offset,
    uint64_t writeBufferLen,
    uint64_t flowControlLen,
    bool fin,
    uint64_t bufMetaStartingOffset) {
  if (packetBuilder.remainingSpace() == 0) {
    return 0;
  }
  if (writeBufferLen == 0 && !fin) {
    return folly::makeUnexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "No data or fin supplied when writing stream."));
  }

  QuicInteger idInt(id);
  auto idIntSize = idInt.getSize();
  if (idIntSize.hasError()) {
    return folly::makeUnexpected(idIntSize.error());
  }
  uint64_t headerSize = sizeof(uint8_t) + idIntSize.value();
  if (packetBuilder.remainingSpace() < headerSize) {
    VLOG(4) << "No space in packet for stream header. stream=" << id
            << " limit=" << packetBuilder.remainingSpace();
    return 0;
  }

  QuicInteger offsetInt(offset);
  if (offset != 0) {
    auto offsetIntSize = offsetInt.getSize();
    if (offsetIntSize.hasError()) {
      return folly::makeUnexpected(offsetIntSize.error());
    }
    headerSize += offsetIntSize.value();
  }
  instructionBuilder.setStreamOffset(offset);

  uint64_t dataLen = std::min(writeBufferLen, flowControlLen);
  dataLen = std::min(dataLen, packetBuilder.remainingSpace() - headerSize);
  bool shouldSetFin = fin && dataLen == writeBufferLen;
  if (dataLen == 0 && !shouldSetFin) {
    return 0;
  }
  if (packetBuilder.remainingSpace() < headerSize) {
    VLOG(4) << "No space in packet for stream header. stream=" << id
            << " limit=" << packetBuilder.remainingSpace();
    return 0;
  }
  DCHECK(dataLen + headerSize <= packetBuilder.remainingSpace());
  instructionBuilder.setLength(dataLen);
  instructionBuilder.setFin(shouldSetFin);
  instructionBuilder.setBufMetaStartingOffset(bufMetaStartingOffset);
  return dataLen + headerSize;
}
} // namespace quic
