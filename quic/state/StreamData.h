/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/container/F14Map.h>
#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>
#include <quic/common/SmallVec.h>
#include <quic/dsr/DSRPacketizationRequestSender.h>
#include <quic/state/QuicPriorityQueue.h>

namespace quic {

/**
 * A buffer representation without the actual data. This is part of the public
 * facing interface.
 *
 * This is experimental.
 */
struct BufferMeta {
  size_t length;

  explicit BufferMeta(size_t lengthIn) : length(lengthIn) {}
};

/**
 * A write buffer representation without the actual data. This is used for
 * write buffer management in a stream.
 *
 * This is experimental.
 */
struct WriteBufferMeta {
  size_t length{0};
  size_t offset{0};
  bool eof{false};

  WriteBufferMeta() = default;

  struct Builder {
    Builder& setLength(size_t lengthIn) {
      length_ = lengthIn;
      return *this;
    }

    Builder& setOffset(size_t offsetIn) {
      offset_ = offsetIn;
      return *this;
    }

    Builder& setEOF(bool val) {
      eof_ = val;
      return *this;
    }

    WriteBufferMeta build() {
      return WriteBufferMeta(length_, offset_, eof_);
    }

   private:
    size_t length_{0};
    size_t offset_{0};
    bool eof_{false};
  };

  WriteBufferMeta split(size_t splitLen) {
    CHECK_GE(length, splitLen);
    auto splitEof = splitLen == length && eof;
    WriteBufferMeta splitOf(splitLen, offset, splitEof);
    offset += splitLen;
    length -= splitLen;
    return splitOf;
  }

 private:
  explicit WriteBufferMeta(size_t lengthIn, size_t offsetIn, bool eofIn)
      : length(lengthIn), offset(offsetIn), eof(eofIn) {}
};

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
  folly::F14FastMap<uint64_t, std::unique_ptr<StreamBuffer>>
      retransmissionBuffer;

  // Tracks intervals which we have received ACKs for. E.g. in the case of all
  // data being acked this would contain one internval from 0 -> the largest
  // offset ACKed. This allows us to track which delivery callbacks can be
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
  // In a non-DSR stream, when we are finished writing out all the bytes until
  // FIN, this will be one greater than finalWriteOffset.
  // When DSR is used, this still points to the starting bytes in the write
  // buffer. Its value won't change with WriteBufferMetas are appended and sent
  // for a stream.
  uint64_t currentWriteOffset{0};

  // the minimum offset requires retransmit
  uint64_t minimumRetransmittableOffset{0};

  // Offset of the next expected bytes that we need to read from
  // the read buffer.
  uint64_t currentReadOffset{0};

  // the smallest data offset that we expect the peer to send.
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

  void removeFromLossBuffer(uint64_t offset, size_t len, bool eof) {
    if (lossBuffer.empty() || len == 0) {
      // Nothing to do.
      return;
    }
    auto lossItr = lossBuffer.begin();
    for (; lossItr != lossBuffer.end(); lossItr++) {
      uint64_t lossStartOffset = lossItr->offset;
      uint64_t lossEndOffset = lossItr->offset + lossItr->data.chainLength();
      uint64_t removedStartOffset = offset;
      uint64_t removedEndOffset = offset + len;
      if (lossStartOffset > removedEndOffset) {
        return;
      }
      // There's two cases. If the removed offset lies within the existing
      // StreamBuffer then we need to potentially split it and remove that
      // section. The other case is that the existing StreamBuffer is completely
      // accounted for by the removed section, in which case it will be removed.
      // Note that this split/trim logic relies on the fact that insertion into
      // the loss buffer will merge contiguous elements, thus allowing us to
      // make these assumptions.
      if ((removedStartOffset >= lossStartOffset &&
           removedEndOffset <= lossEndOffset) ||
          (lossStartOffset >= removedStartOffset &&
           lossEndOffset <= removedEndOffset)) {
        size_t amountToSplit = removedStartOffset > lossStartOffset
            ? removedStartOffset - lossStartOffset
            : 0;
        Buf splitBuf = nullptr;
        if (amountToSplit > 0) {
          splitBuf = lossItr->data.splitAtMost(amountToSplit);
          CHECK(splitBuf);
          lossItr->offset += amountToSplit;
        }
        lossItr->offset += lossItr->data.trimStartAtMost(len);
        if (lossItr->data.empty() && lossItr->eof == eof) {
          lossBuffer.erase(lossItr);
        }
        if (splitBuf) {
          insertIntoLossBuffer(std::make_unique<StreamBuffer>(
              std::move(splitBuf), lossStartOffset, false));
        }
        return;
      }
    }
  }
};

struct QuicConnectionStateBase;

enum class StreamSendState : uint8_t { Open, ResetSent, Closed, Invalid };

enum class StreamRecvState : uint8_t { Open, Closed, Invalid };

inline folly::StringPiece streamStateToString(StreamSendState state) {
  switch (state) {
    case StreamSendState::Open:
      return "Open";
    case StreamSendState::ResetSent:
      return "ResetSent";
    case StreamSendState::Closed:
      return "Closed";
    case StreamSendState::Invalid:
      return "Invalid";
  }
  return "Unknown";
}

inline folly::StringPiece streamStateToString(StreamRecvState state) {
  switch (state) {
    case StreamRecvState::Open:
      return "Open";
    case StreamRecvState::Closed:
      return "Closed";
    case StreamRecvState::Invalid:
      return "Invalid";
  }
  return "Unknown";
}

struct QuicStreamState : public QuicStreamLike {
  virtual ~QuicStreamState() override = default;

  QuicStreamState(StreamId id, QuicConnectionStateBase& conn);

  QuicStreamState(
      StreamId idIn,
      const folly::Optional<StreamGroupId>& groupIdIn,
      QuicConnectionStateBase& connIn);

  QuicStreamState(QuicStreamState&&) = default;

  /**
   * Constructor to migrate QuicStreamState to another
   * QuicConnectionStateBase.
   */
  QuicStreamState(QuicConnectionStateBase& connIn, QuicStreamState&& other)
      : QuicStreamLike(std::move(other)),
        conn(connIn),
        id(other.id),
        groupId(other.groupId) {
    // QuicStreamState fields
    finalWriteOffset = other.finalWriteOffset;
    flowControlState = other.flowControlState;
    streamReadError = other.streamReadError;
    streamWriteError = other.streamWriteError;
    sendState = other.sendState;
    recvState = other.recvState;
    isControl = other.isControl;
    lastHolbTime = other.lastHolbTime;
    totalHolbTime = other.totalHolbTime;
    holbCount = other.holbCount;
    priority = other.priority;
    dsrSender = std::move(other.dsrSender);
    writeBufMeta = other.writeBufMeta;
    retransmissionBufMetas = std::move(other.retransmissionBufMetas);
    lossBufMetas = std::move(other.lossBufMetas);
  }

  // Connection that this stream is associated with.
  QuicConnectionStateBase& conn;

  // Stream id of the connection.
  StreamId id;

  // ID of the group the stream belongs to.
  folly::Optional<StreamGroupId> groupId;

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
  StreamSendState sendState{StreamSendState::Open};

  // State machine data
  StreamRecvState recvState{StreamRecvState::Open};

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
    bool sendInTerminalState = sendState == StreamSendState::Closed ||
        sendState == StreamSendState::Invalid;

    bool recvInTerminalState = recvState == StreamRecvState::Closed ||
        recvState == StreamRecvState::Invalid;

    return sendInTerminalState && recvInTerminalState;
  }

  // If the stream is still writable.
  bool writable() const {
    return sendState == StreamSendState::Open && !finalWriteOffset.has_value();
  }

  bool shouldSendFlowControl() const {
    return recvState == StreamRecvState::Open;
  }

  // If the stream has writable data that's not backed by DSR. That is, in a
  // regular stream write, it will be able to write something. So it either
  // needs to have writeBuffer, or it has EOF to send.
  bool hasWritableData() const {
    if (!writeBuffer.empty()) {
      CHECK_GE(flowControlState.peerAdvertisedMaxOffset, currentWriteOffset);
      return flowControlState.peerAdvertisedMaxOffset - currentWriteOffset > 0;
    }
    if (finalWriteOffset) {
      /**
       * This is the case that EOF/FIN is the only thing we can write in a
       * non-DSR write for a stream. It's actually OK to send out a FIN with
       * correct offset before we send out DSRed bytes. Peer is supposed to be
       * able to handle this. But it's also not hard to limit it. So here i'm
       * gonna go with the safer path: do not write FIN only stream frame if we
       * still have BufMetas to send.
       */
      return writeBufMeta.length == 0 &&
          currentWriteOffset <= *finalWriteOffset &&
          writeBufMeta.offset <= *finalWriteOffset;
    }
    return false;
  }

  FOLLY_NODISCARD bool hasWritableBufMeta() const {
    if (writeBufMeta.offset == 0) {
      return false;
    }
    if (writeBufMeta.length > 0) {
      CHECK_GE(flowControlState.peerAdvertisedMaxOffset, writeBufMeta.offset);
      return flowControlState.peerAdvertisedMaxOffset - writeBufMeta.offset > 0;
    }
    if (finalWriteOffset) {
      return writeBufMeta.offset <= *finalWriteOffset;
    }
    return false;
  }

  FOLLY_NODISCARD bool hasSentFIN() const {
    if (!finalWriteOffset) {
      return false;
    }
    return currentWriteOffset > *finalWriteOffset ||
        writeBufMeta.offset > *finalWriteOffset;
  }

  FOLLY_NODISCARD bool hasLoss() const {
    return !lossBuffer.empty() || !lossBufMetas.empty();
  }

  FOLLY_NODISCARD uint64_t nextOffsetToWrite() const {
    // The stream has never had WriteBufferMetas. Then currentWriteOffset
    // always points to the next offset we send. This of course relies on the
    // current contract of DSR: Real data always comes first. This code (and a
    // lot other code) breaks when that contract is breached.
    if (writeBufMeta.offset == 0) {
      return currentWriteOffset;
    }
    if (!writeBuffer.empty()) {
      return currentWriteOffset;
    }
    return writeBufMeta.offset;
  }

  bool hasReadableData() const {
    return (readBuffer.size() > 0 &&
            currentReadOffset == readBuffer.front().offset) ||
        (finalReadOffset && currentReadOffset == *finalReadOffset);
  }

  bool hasPeekableData() const {
    return readBuffer.size() > 0;
  }

  std::unique_ptr<DSRPacketizationRequestSender> dsrSender;

  // BufferMeta that has been writen to the QUIC layer.
  // When offset is 0, nothing has been written to it. On first write, its
  // starting offset will be currentWriteOffset + writeBuffer.chainLength().
  WriteBufferMeta writeBufMeta;

  // A map to store sent WriteBufferMetas for potential retransmission.
  folly::F14FastMap<uint64_t, WriteBufferMeta> retransmissionBufMetas;

  // WriteBufferMetas that's already marked lost. They will be retransmitted.
  std::deque<WriteBufferMeta> lossBufMetas;

  /**
   * Insert a new WriteBufferMeta into lossBufMetas. If the new WriteBufferMeta
   * can be append to an existing WriteBufferMeta, it will be appended. Note
   * it won't be prepended to an existing WriteBufferMeta. And it will also not
   * merge 3 WriteBufferMetas together if the new one happens to fill up a hole
   * between 2 existing WriteBufferMetas.
   */
  void insertIntoLossBufMeta(WriteBufferMeta bufMeta) {
    auto lossItr = std::upper_bound(
        lossBufMetas.begin(),
        lossBufMetas.end(),
        bufMeta.offset,
        [](auto offset, const auto& wBufMeta) {
          return offset < wBufMeta.offset;
        });
    if (!lossBufMetas.empty() && lossItr != lossBufMetas.begin() &&
        std::prev(lossItr)->offset + std::prev(lossItr)->length ==
            bufMeta.offset) {
      std::prev(lossItr)->length += bufMeta.length;
      std::prev(lossItr)->eof = bufMeta.eof;
    } else {
      lossBufMetas.insert(lossItr, bufMeta);
    }
  }
};
} // namespace quic
