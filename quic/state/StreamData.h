/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/state/StateMachine.h>

namespace quic {

struct StreamBuffer {
  folly::IOBufQueue data;
  uint64_t offset;
  bool eof{false};

  StreamBuffer(Buf dataIn, uint64_t offsetIn, bool eofIn = false) noexcept
      : data(folly::IOBufQueue::cacheChainLength()),
        offset(offsetIn),
        eof(eofIn) {
    data.append(std::move(dataIn));
  }

  StreamBuffer(StreamBuffer&& other) = default;
  StreamBuffer& operator=(StreamBuffer&& other) = default;
};

struct QuicStreamLike {
  virtual ~QuicStreamLike() = default;

  // List of bytes that have been read and buffered. We need to buffer
  // bytes in case we get bytes out of order.
  std::deque<StreamBuffer> readBuffer;

  // List of bytes that have been written to the QUIC layer.
  folly::IOBufQueue writeBuffer{folly::IOBufQueue::cacheChainLength()};

  // Stores a list of buffers which have been written to the socket and are
  // currently un-acked. Each one represents one StreamFrame that was written.
  // We need to buffer these because these might be retransmitted
  // in the future.
  // These are sorted in order of start offset.
  std::deque<StreamBuffer> retransmissionBuffer;

  // Stores a list of buffers which have been marked as loss by loss detector.
  // Each one represents one StreamFrame that was written.
  std::deque<StreamBuffer> lossBuffer;

  // Current offset of the start bytes in the write buffer.
  // This changes when we pop stuff off the writeBuffer.
  // When we are finished writing out all the bytes until FIN, this will
  // be one greater than finalWriteOffset.
  uint64_t currentWriteOffset{0};

  // the minimum offset requires retransmit
  // N.B. used in QUIC partial reliability
  uint64_t minimumRetransmittableOffset{0};

  // Offset of the next expected bytes that we need to read from
  // the read buffer.
  uint64_t currentReadOffset{0};

  // the smallest data offset that we expect the peer to send.
  // N.B. used in QUIC partial reliability
  uint64_t currentReceiveOffset{0};

  // Maximum byte offset observed on the stream.
  uint64_t maxOffsetObserved{0};

  // If an EOF is observed on the stream, the position of the EOF. It could be
  // either from FIN or RST. Right now we use one value to represent both FIN
  // and RST. We may split write EOF into two values in the future.
  // Read side eof offset.
  folly::Optional<uint64_t> finalReadOffset;
};

struct QuicConnectionStateBase;

struct StreamStates {
  // The stream is open
  struct Open {};

  // The stream has closed its write
  struct HalfClosedLocal {};

  // The stream has closed read.
  struct HalfClosedRemote {};

  // The stream is waiting for the ack of the reset stream
  struct WaitingForRstAck {};

  // The stream is now closed.
  struct Closed {};
};

using StreamStateData = boost::variant<
    StreamStates::Open,
    StreamStates::HalfClosedLocal,
    StreamStates::HalfClosedRemote,
    StreamStates::WaitingForRstAck,
    StreamStates::Closed>;

inline std::string streamStateToString(const StreamStateData& state) {
  return folly::variant_match(
      state,
      [](const StreamStates::Open&) { return "Open"; },
      [](const StreamStates::HalfClosedLocal&) { return "HalfClosedLocal"; },
      [](const StreamStates::HalfClosedRemote&) { return "HalfClosedRemote"; },
      [](const StreamStates::WaitingForRstAck&) { return "WaitingForRstAck"; },
      [](const StreamStates::Closed&) { return "Closed"; });
}

struct QuicStreamState : public QuicStreamLike {
  virtual ~QuicStreamState() override = default;

  QuicStreamState(StreamId id, QuicConnectionStateBase& conn);

  // Connection that this stream is associated with.
  QuicConnectionStateBase& conn;

  // Stream id of the connection.
  StreamId id;

  // Write side eof offset. This represents only the final FIN offset.
  folly::Optional<uint64_t> finalWriteOffset;

  struct StreamFlowControlState {
    uint64_t windowSize{0};
    uint64_t advertisedMaxOffset{0};
    uint64_t peerAdvertisedMaxOffset{0};
    // Time at which the last flow control update was sent by the transport.
    folly::Optional<TimePoint> timeOfLastFlowControlUpdate;
  };

  StreamFlowControlState flowControlState;

  // Stream level read error occured.
  folly::Optional<QuicErrorCode> streamReadError;
  // Stream level write error occured.
  folly::Optional<QuicErrorCode> streamWriteError;

  // State machine data
  StreamStateData state{StreamStates::Open()};

  // The packet number of the latest packet that contains a MaxStreamDataFrame
  // sent out by us.
  folly::Optional<PacketNum> latestMaxStreamDataPacket;

  // Tells whether this stream is a control stream.
  // It is set by the app via setControlStream and the transport can use this
  // knowledge for optimizations e.g. for setting the app limited state on
  // congestion control with control streams still active.
  bool isControl{false};

  // The last time we detected we were head of line blocked on the stream.
  folly::Optional<Clock::time_point> lastHolbTime;

  // The total amount of time we are head line blocked on the stream.
  std::chrono::microseconds totalHolbTime{std::chrono::microseconds::zero()};

  // Number of times the stream has entered the HOLB state
  // lastHolbTime indicates whether the stream is HOL blocked at the moment.
  uint32_t holbCount{0};

  // If the stream is still writable.
  bool writable() const {
    return matchesStates<
               StreamStateData,
               StreamStates::Open,
               StreamStates::HalfClosedRemote>(state) &&
        !finalWriteOffset.hasValue();
  }

  bool shouldSendFlowControl() const {
    return matchesStates<
        StreamStateData,
        StreamStates::Open,
        StreamStates::HalfClosedLocal>(state);
  }

  bool hasWritableData() const {
    if (!writeBuffer.empty()) {
      return flowControlState.peerAdvertisedMaxOffset - currentWriteOffset > 0;
    }
    if (finalWriteOffset) {
      return currentWriteOffset <= *finalWriteOffset;
    }
    return false;
  }

  bool hasReadableData() const {
    return (readBuffer.size() > 0 &&
            currentReadOffset == readBuffer.front().offset) ||
        (finalReadOffset && currentReadOffset == *finalReadOffset);
  }

  bool hasPeekableData() const {
    return readBuffer.size() > 0;
  }
};
} // namespace quic
