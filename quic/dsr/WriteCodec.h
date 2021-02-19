/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/dsr/Types.h>
#include <optional>

namespace quic {

struct DSRStreamFrameWriteResult {
  SendInstruction sendInstruction;
  uint32_t encodedSize;

  explicit DSRStreamFrameWriteResult(SendInstruction instruction, uint32_t size)
      : sendInstruction(std::move(instruction)), encodedSize(size) {}
};

std::optional<DSRStreamFrameWriteResult> writeDSRStreamFrame(
    size_t packetSizeLimit,
    StreamId id,
    uint64_t offset,
    uint64_t writeBufferLen,
    uint64_t flowControlLen,
    bool fin) {
  if (packetSizeLimit == 0) {
    return std::nullopt;
  }
  if (writeBufferLen == 0 && !fin) {
    throw QuicInternalException(
        "No data or fin supplied when writing stream.",
        LocalErrorCode::INTERNAL_ERROR);
  }

  StreamTypeField::Builder streamTypeBuilder;
  QuicInteger idInt(id);
  uint64_t headerSize = sizeof(uint8_t) + idInt.getSize();
  if (packetSizeLimit < headerSize) {
    VLOG(4) << "No space in packet for stream header. stream=" << id
            << " limit=" << packetSizeLimit;
    return std::nullopt;
  }

  QuicInteger offsetInt(offset);
  if (offset != 0) {
    streamTypeBuilder.setOffset();
    headerSize += offsetInt.getSize();
  }
  SendInstruction::Builder builder(id);
  builder.setOffset(offset);

  uint64_t dataLen = std::min(writeBufferLen, flowControlLen);
  dataLen = std::min(dataLen, packetSizeLimit - headerSize);
  bool shouldSetFin = fin && dataLen == writeBufferLen;
  if (dataLen == 0 && !shouldSetFin) {
    return std::nullopt;
  }
  if (packetSizeLimit < headerSize) {
    VLOG(4) << "No space in packet for stream header. stream=" << id
            << " limit=" << packetSizeLimit;
    return std::nullopt;
  }
  DCHECK(dataLen + headerSize <= packetSizeLimit);
  builder.setLength(dataLen);
  builder.setFin(shouldSetFin);
  return DSRStreamFrameWriteResult(builder.build(), dataLen + headerSize);
}

} // namespace quic
