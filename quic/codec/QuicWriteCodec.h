/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/common/CircularDeque.h>
#include <quic/common/IntervalSet.h>
#include <quic/state/TransportSettings.h>
#include <sys/types.h>
#include <chrono>
#include <cstdint>

namespace quic {

// Ack and PacketNumber states. This is per-packet number space.
struct WriteAckState {
  AckBlocks acks;

  // Receive timestamp and packet number for the largest received packet.
  //
  // Updated whenever we receive a packet with a larger packet number
  // than all previously received packets in the packet number space
  // tracked by this AckState.
  folly::Optional<RecvdPacketInfo> largestRecvdPacketInfo;
  // Receive timestamp and packet number for the last received packet.
  //
  // Will be different from the value stored in largestRecvdPacketInfo
  // if the last packet was received out of order and thus had a packet
  // number less than that of a previously received packet in the packet
  // number space tracked by this AckState.
  folly::Optional<RecvdPacketInfo> lastRecvdPacketInfo;

  // Packet number and timestamp of recently received packets.
  //
  // The maximum number of packets stored in pktsReceivedTimestamps is
  // controlled by kMaxReceivedPktsTimestampsStored.
  //
  // The packet number of entries in the deque is guarenteed to increase
  // monotonically because an entry is only added for a received packet
  // if the packet number is greater than the packet number of the last
  // element in the deque (e.g., entries are not added for packets that
  // arrive out of order relative to previously received packets).
  CircularDeque<RecvdPacketInfo> recvdPacketInfos;
};

struct AckFrameMetaData {
  // ACK state.
  const WriteAckState& ackState;

  // Delay in sending ack from time that packet was received.
  std::chrono::microseconds ackDelay;
  // The ack delay exponent to use.
  uint8_t ackDelayExponent;

  // Receive timestamps basis
  TimePoint connTime;

  folly::Optional<AckReceiveTimestampsConfig> recvTimestampsConfig =
      folly::none;

  folly::Optional<uint64_t> maxAckReceiveTimestampsToSend = folly::none;
};

struct AckFrameWriteResult {
  uint64_t bytesWritten;
  WriteAckFrame writeAckFrame;
  // This includes the first ack block
  size_t ackBlocksWritten;
  size_t timestampRangesWritten;
  size_t timestampsWritten;
  AckFrameWriteResult(
      uint64_t bytesWrittenIn,
      WriteAckFrame writeAckFrameIn,
      size_t ackBlocksWrittenIn,
      size_t timestampRangesWrittenIn = 0,
      size_t timestampsWrittenIn = 0)
      : bytesWritten(bytesWrittenIn),
        writeAckFrame(writeAckFrameIn),
        ackBlocksWritten(ackBlocksWrittenIn),
        timestampRangesWritten(timestampRangesWrittenIn),
        timestampsWritten(timestampsWrittenIn) {}
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
    PacketBuilderInterface& builder,
    FrameType frameType = FrameType::ACK);

/**
 * Helper functions to write the fields for ACK_RECEIVE_TIMESTAMPS frame
 */
size_t computeSizeUsedByRecvdTimestamps(quic::WriteAckFrame& writeAckFrame);

folly::Optional<AckFrameWriteResult> writeAckFrameWithReceivedTimestamps(
    const AckFrameMetaData& ackFrameMetaData,
    PacketBuilderInterface& builder,
    FrameType frameType = FrameType::ACK_RECEIVE_TIMESTAMPS);

folly::Optional<quic::WriteAckFrame> writeAckFrameToPacketBuilder(
    const quic::AckFrameMetaData& ackFrameMetaData,
    quic::PacketBuilderInterface& builder,
    quic::FrameType frameType);

} // namespace quic
// namespace quic
// namespace quic
// namespace quic
