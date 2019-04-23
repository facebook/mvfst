/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.
#pragma once

#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/common/IntervalSet.h>
#include <chrono>

namespace quic {

struct AckFrameMetaData {
  // Ack blocks. There must be at least 1 ACK block to send.
  const IntervalSet<PacketNum>& ackBlocks;
  // Delay in sending ack from time that packet was received.
  std::chrono::microseconds ackDelay;
  // The ack delay exponent to use.
  uint8_t ackDelayExponent;

  AckFrameMetaData(
      const IntervalSet<PacketNum>& acksIn,
      std::chrono::microseconds ackDelayIn,
      uint8_t ackDelayExponentIn)
      : ackBlocks(acksIn),
        ackDelay(ackDelayIn),
        ackDelayExponent(ackDelayExponentIn) {}
};

struct StreamFrameMetaData {
  StreamId id{0};
  uint64_t offset{0};
  bool fin{false};
  Buf data;
  bool hasMoreFrames{true};

  StreamFrameMetaData() = default;
  StreamFrameMetaData(
      StreamId idIn,
      uint64_t offsetIn,
      bool finIn,
      Buf bufIn,
      bool hasMoreFramesIn)
      : id(idIn),
        offset(offsetIn),
        fin(finIn),
        data(std::move(bufIn)),
        hasMoreFrames(hasMoreFramesIn) {}
};

struct StreamFrameWriteResult {
  // The number of bytes written to the stream data section
  uint64_t bytesWritten;
  bool finWritten;
  Buf writtenData;

  explicit StreamFrameWriteResult(
      uint64_t bytesWrittenIn,
      bool finWrittenIn,
      Buf writtenDataIn)
      : bytesWritten(bytesWrittenIn),
        finWritten(finWrittenIn),
        writtenData(std::move(writtenDataIn)) {}
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
 * Write a StreamFrame into builder
 *
 * WriteCodec will take as much as it can to append it to the appender. Input
 * data, Stream id and offset are passed in via streamFrameMetaData.
 *
 * Return: A StreamFrameWriteResult to indicate how many bytes of data (not
 * including other stream frame fields) are written to the stream
 */
folly::Optional<StreamFrameWriteResult> writeStreamFrame(
    const StreamFrameMetaData& streamFrameMetaData,
    PacketBuilderInterface& builder);

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
folly::Optional<WriteCryptoFrame>
writeCryptoFrame(uint64_t offsetIn, Buf data, PacketBuilderInterface& builder);

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
