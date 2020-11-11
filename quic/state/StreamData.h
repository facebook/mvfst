/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/container/F14Map.h>
#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/common/SmallVec.h>
#include <quic/state/QuicPriorityQueue.h>

namespace quic {

struct StreamBuffer {
  BufQueue data;
  uint64_t offset;
  bool eof{false};

  StreamBuffer(Buf dataIn, uint64_t offsetIn, bool eofIn = false) noexcept
      : data(std::move(dataIn)), offset(offsetIn), eof(eofIn) {}

  StreamBuffer(StreamBuffer&& other) = default;
  StreamBuffer& operator=(StreamBuffer&& other) = default;
};

struct QuicStreamLike {
  QuicStreamLike() = default;

  QuicStreamLike(QuicStreamLike&&) = default;

  virtual ~QuicStreamLike() = default;

  // List of bytes that have been read and buffered. We need to buffer
  // bytes in case we get bytes out of order.
  std::deque<StreamBuffer> readBuffer;

  // List of bytes that have been written to the QUIC layer.
  BufQueue writeBuffer{};

  // Stores a map of offset:buffers which have been written to the socket and
  // are currently un-acked. Each one represents one StreamFrame that was
  // written. We need to buffer these because these might be retransmitted in
  // the future. These are associated with the starting offset of the buffer.
  // Note: the offset in the StreamBuffer itself can be >= the offset on which
  // it is keyed due to partial reliability - when data is skipped the offset
  // in the StreamBuffer may be incremented, but the keyed offset must remain
  // the same so it can be removed from the buffer on ACK.
  folly::F14FastMap<uint64_t, std::unique_ptr<StreamBuffer>>
      retransmissionBuffer;

  // Tracks intervals which we have received ACKs for. E.g. in the case of all
  // data being acked this would contain one internval from 0 -> the largest
  // offseet ACKed. This allows us to track which delivery callbacks can be
  // called.
  template <class T>
  using IntervalSetVec = SmallVec<T, 32, uint16_t>;
  using AckedIntervals = IntervalSet<uint64_t, 1, IntervalSetVec>;
  AckedIntervals ackedIntervals;

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

  // Current cumulative number of packets sent for this stream. It only counts
  // egress packets that contains a *new* STREAM frame for this stream.
  uint64_t numPacketsTxWithNewData{0};

  /*
   * Either insert a new entry into the loss buffer, or merge the buffer with
   * an existing entry.
   */
  void insertIntoLossBuffer(std::unique_ptr<StreamBuffer> buf) {
    // We assume here that we won't try to insert an overlapping buffer, as
    // that should never happen in the loss buffer.
    auto lossItr = std::upper_bound(
        lossBuffer.begin(),
        lossBuffer.end(),
        buf->offset,
        [](auto offset, const auto& buffer) { return offset < buffer.offset; });
    if (!lossBuffer.empty() && lossItr != lossBuffer.begin() &&
        std::prev(lossItr)->offset + std::prev(lossItr)->data.chainLength() ==
            buf->offset) {
      std::prev(lossItr)->data.append(buf->data.move());
      std::prev(lossItr)->eof = buf->eof;
    } else {
      lossBuffer.insert(lossItr, std::move(*buf));
    }
  }
};

struct QuicConnectionStateBase;

enum class StreamSendState : uint8_t {
  Open_E,
  ResetSent_E,
  Closed_E,
  Invalid_E
};

enum class StreamRecvState : uint8_t { Open_E, Closed_E, Invalid_E };

inline folly::StringPiece streamStateToString(StreamSendState state) {
  switch (state) {
    case StreamSendState::Open_E:
      return "Open";
    case StreamSendState::ResetSent_E:
      return "ResetSent";
    case StreamSendState::Closed_E:
      return "Closed";
    case StreamSendState::Invalid_E:
      return "Invalid";
  }
  return "Unknown";
}

inline folly::StringPiece streamStateToString(StreamRecvState state) {
  switch (state) {
    case StreamRecvState::Open_E:
      return "Open";
    case StreamRecvState::Closed_E:
      return "Closed";
    case StreamRecvState::Invalid_E:
      return "Invalid";
  }
  return "Unknown";
}

struct QuicStreamState : public QuicStreamLike {
  virtual ~QuicStreamState() override = default;

  QuicStreamState(StreamId id, QuicConnectionStateBase& conn);

  QuicStreamState(QuicStreamState&&) = default;

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
  StreamSendState sendState{StreamSendState::Open_E};

  // State machine data
  StreamRecvState recvState{StreamRecvState::Open_E};

  // Tells whether this stream is a control stream.
  // It is set by the app via setControlStream and the transport can use this
  // knowledge for optimizations e.g. for setting the app limited state on
  // congestion control with control streams still active.
  bool isControl{false};

  // The last time we detected we were head of line blocked on the stream.
  folly::Optional<Clock::time_point> lastHolbTime;

  // The total amount of time we are head line blocked on the stream.
  std::chrono::microseconds totalHolbTime{0us};

  // Number of times the stream has entered the HOLB state
  // lastHolbTime indicates whether the stream is HOL blocked at the moment.
  uint32_t holbCount{0};

  Priority priority{kDefaultPriority};

  // Returns true if both send and receive state machines are in a terminal
  // state
  bool inTerminalStates() const {
    bool sendInTerminalState = sendState == StreamSendState::Closed_E ||
        sendState == StreamSendState::Invalid_E;

    bool recvInTerminalState = recvState == StreamRecvState::Closed_E ||
        recvState == StreamRecvState::Invalid_E;

    return sendInTerminalState && recvInTerminalState;
  }

  // If the stream is still writable.
  bool writable() const {
    return sendState == StreamSendState::Open_E &&
        !finalWriteOffset.has_value();
  }

  bool shouldSendFlowControl() const {
    return recvState == StreamRecvState::Open_E;
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
