/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Optional.h>
#include <quic/dsr/PacketBuilder.h>
#include <quic/dsr/Types.h>

namespace quic {

struct DSRStreamFrameWriteResult {
  SendInstruction sendInstruction;
  uint32_t encodedSize;

  explicit DSRStreamFrameWriteResult(SendInstruction instruction, uint32_t size)
      : sendInstruction(std::move(instruction)), encodedSize(size) {}
};

folly::Optional<DSRStreamFrameWriteResult> writeDSRStreamFrame(
    DSRPacketBuilderBase& packetBuilder,
    StreamId id,
    uint64_t offset,
    uint64_t writeBufferLen,
    uint64_t flowControlLen,
    bool fin) {
  if (packetBuilder.remainingSpace() == 0) {
    return folly::none;
  }
  if (writeBufferLen == 0 && !fin) {
    throw QuicInternalException(
        "No data or fin supplied when writing stream.",
        LocalErrorCode::INTERNAL_ERROR);
  }

  StreamTypeField::Builder streamTypeBuilder;
  QuicInteger idInt(id);
  uint64_t headerSize = sizeof(uint8_t) + idInt.getSize();
  if (packetBuilder.remainingSpace() < headerSize) {
    VLOG(4) << "No space in packet for stream header. stream=" << id
            << " limit=" << packetBuilder.remainingSpace();
    return folly::none;
  }

  QuicInteger offsetInt(offset);
  if (offset != 0) {
    streamTypeBuilder.setOffset();
    headerSize += offsetInt.getSize();
  }
  SendInstruction::Builder builder(id);
  builder.setOffset(offset);

  uint64_t dataLen = std::min(writeBufferLen, flowControlLen);
  dataLen = std::min(dataLen, packetBuilder.remainingSpace() - headerSize);
  bool shouldSetFin = fin && dataLen == writeBufferLen;
  if (dataLen == 0 && !shouldSetFin) {
    return folly::none;
  }
  if (packetBuilder.remainingSpace() < headerSize) {
    VLOG(4) << "No space in packet for stream header. stream=" << id
            << " limit=" << packetBuilder.remainingSpace();
    return folly::none;
  }
  DCHECK(dataLen + headerSize <= packetBuilder.remainingSpace());
  builder.setLength(dataLen);
  builder.setFin(shouldSetFin);
  return DSRStreamFrameWriteResult(builder.build(), dataLen + headerSize);
}

} // namespace quic
