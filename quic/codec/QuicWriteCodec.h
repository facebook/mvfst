/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/common/IntervalSet.h>
#include <chrono>

namespace quic {

struct AckFrameMetaData {
  // Ack blocks. There must be at least 1 ACK block to send.
  const AckBlocks& ackBlocks;
  // Delay in sending ack from time that packet was received.
  std::chrono::microseconds ackDelay;
  // The ack delay exponent to use.
  uint8_t ackDelayExponent;

  AckFrameMetaData(
      const AckBlocks& acksIn,
      std::chrono::microseconds ackDelayIn,
      uint8_t ackDelayExponentIn)
      : ackBlocks(acksIn),
        ackDelay(ackDelayIn),
        ackDelayExponent(ackDelayExponentIn) {}
};

struct AckFrameWriteResult {
  uint64_t bytesWritten;
  // This includes the first ack block
  size_t ackBlocksWritten;

  AckFrameWriteResult(uint64_t bytesWrittenIn, size_t ackBlocksWrittenIn)
      : bytesWritten(bytesWrittenIn), ackBlocksWritten(ackBlocksWrittenIn) {}
};

/**
 * Write a simple QuicFrame into builder
 *
 * The input parameter is the frame to be written to the output appender.
 *
 */
size_t writeSimpleFrame(
    QuicSimpleFrame&& frame,
    PacketBuilderInterface& builder);

/**
 * Write a (non-ACK, non-Stream) QuicFrame into builder
 *
 * The input parameter is the frame to be written to the output appender.
 *
 */
size_t writeFrame(QuicWriteFrame&& frame, PacketBuilderInterface& builder);

/**
 * Write a complete stream frame header into builder
 * This writes the stream frame header into the parameter builder and returns
 * the bytes of data that can be written following the header. The number of
 * bytes are communicated by an optional that can be >= 0. It is expected that
 * the call is followed by writeStreamFrameData.
 *
 * skipLenHint: When this value is present, caller will decide if the stream
 *   length field should be skipped. Otherwise, the function has its own logic
 *   to decide it. When skipLenHint is true, the field is skipped. When it's
 *   false, it will be encoded into the header.
 */
folly::Optional<uint64_t> writeStreamFrameHeader(
    PacketBuilderInterface& builder,
    StreamId id,
    uint64_t offset,
    uint64_t writeBufferLen,
    uint64_t flowControlLen,
    bool fin,
    folly::Optional<bool> skipLenHint,
    folly::Optional<StreamGroupId> streamGroupId = folly::none);

/**
 * Write stream frama data into builder
 * This writes dataLen worth of bytes from the parameter writeBuffer into the
 * parameter builder. This should only be called after a complete stream header
 * has been written by writeStreamFrameHeader.
 */
void writeStreamFrameData(
    PacketBuilderInterface& builder,
    const BufQueue& writeBuffer,
    uint64_t dataLen);

/**
 * Write stream frama data into builder
 * This writes dataLen worth of bytes from the parameter writeBuffer into the
 * parameter builder. This should only be called after a complete stream header
 * has been written by writeStreamFrameHeader.
 */
void writeStreamFrameData(
    PacketBuilderInterface& builder,
    Buf writeBuffer,
    uint64_t dataLen);

/**
 * Write a CryptoFrame into builder. The builder may not be able to accept all
 * the bytes that are supplied to writeCryptoFrame.
 *
 * offset is the offset of the crypto frame to write into the builder
 * data is the actual data that needs to be written.
 *
 * Return: A WriteCryptoFrame which represents the crypto frame that was
 * written. The caller should check the structure to confirm how many bytes were
 * written.
 */
folly::Optional<WriteCryptoFrame> writeCryptoFrame(
    uint64_t offsetIn,
    const BufQueue& data,
    PacketBuilderInterface& builder);

/**
 * Write a AckFrame into builder
 *
 * Similar to writeStreamFrame, the codec will give a best effort to write as
 * many as AckBlock as it can. The WriteCodec may not be able to write
 * all of them though. A vector of AckBlocks, the largest acked bytes and other
 * ACK frame specific info are passed via ackFrameMetaData.
 *
 * The ackBlocks are supposed to be sorted in descending order
 * of the packet sequence numbers. Exception will be thrown if they are not
 * sorted.
 *
 * Return: A AckFrameWriteResult to indicate how many bytes and ack blocks are
 * written to the appender. Returns an empty optional if an ack block could not
 * be written.
 */
folly::Optional<AckFrameWriteResult> writeAckFrame(
    const AckFrameMetaData& ackFrameMetaData,
    PacketBuilderInterface& builder);
} // namespace quic
