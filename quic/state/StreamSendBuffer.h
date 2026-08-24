/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <cstdint>

#include <quic/QuicConstants.h>
#include <quic/common/CircularDeque.h>
#include <quic/common/FunctionRef.h>
#include <quic/common/IntervalSet.h>
#include <quic/common/Optional.h>

namespace quic {

class StreamSendBuffer {
 public:
  struct SendRange {
    uint64_t offset{0};
    uint64_t len{0};
    // FIN is valid only when offset + len equals the buffer's tail offset.
    bool fin{false};

    friend bool operator==(const SendRange& lhs, const SendRange& rhs) {
      return lhs.offset == rhs.offset && lhs.len == rhs.len &&
          lhs.fin == rhs.fin;
    }
  };

  struct AckResult {
    uint64_t newlyAckedBytes{0};
    bool newlyAckedFin{false};
  };

  using DataWriter = FunctionRef<bool(ByteRange)>;

  StreamSendBuffer() = default;
  ~StreamSendBuffer() = default;
  StreamSendBuffer(const StreamSendBuffer&) = delete;
  StreamSendBuffer& operator=(const StreamSendBuffer&) = delete;
  StreamSendBuffer(StreamSendBuffer&&) noexcept = default;
  StreamSendBuffer& operator=(StreamSendBuffer&&) noexcept = default;

  [[nodiscard]] bool canAppend(uint64_t len) const {
    return !writeClosed_ && !cancelled_ && len <= kMaxVarInt - tailOffset_;
  }

  [[nodiscard]] bool append(BufPtr data, bool fin);

  // maxLen limits payload bytes; FIN-only ranges can still be returned at 0.
  [[nodiscard]] Optional<SendRange> nextNewData(uint64_t maxLen) const;
  [[nodiscard]] Optional<SendRange> nextLoss(uint64_t maxLen) const;

  // The writer can observe a valid prefix before a later missing range fails.
  [[nodiscard]] bool writeAt(uint64_t offset, uint64_t len, DataWriter writer)
      const;

  [[nodiscard]] bool markNewDataSent(const SendRange& range);
  void markLoss(const SendRange& range);
  void markRetransmissionSent(const SendRange& range);
  [[nodiscard]] Optional<AckResult> markAcked(const SendRange& range);

  [[nodiscard]] bool truncateFrom(uint64_t offset);
  void cancelAll();

  [[nodiscard]] uint64_t tailOffset() const {
    return tailOffset_;
  }

  [[nodiscard]] uint64_t nextUnsentOffset() const {
    return nextUnsentOffset_;
  }

  [[nodiscard]] uint64_t unsentBytes() const {
    return tailOffset_ - nextUnsentOffset_;
  }

  [[nodiscard]] uint64_t outstandingBytes() const {
    return outstandingBytes_;
  }

  [[nodiscard]] bool hasPendingLoss() const {
    return !pendingRetransmissions_.empty() || finLost_;
  }

  [[nodiscard]] bool finBuffered() const {
    return finBuffered_;
  }

  [[nodiscard]] bool finSent() const {
    return finSent_;
  }

  [[nodiscard]] bool finLost() const {
    return finLost_;
  }

  [[nodiscard]] bool finAcked() const {
    return finAcked_;
  }

  [[nodiscard]] bool cancelled() const {
    return cancelled_;
  }

  [[nodiscard]] bool allBytesAckedTill(uint64_t offset) const;

  [[nodiscard]] Optional<uint64_t> largestDeliverableOffset() const;

  [[nodiscard]] uint64_t ackInsertVersion() const {
    return ackedIntervals_.insertVersion();
  }

 private:
  struct Entry {
    uint64_t offset;
    uint64_t len;
    BufPtr data;
  };

  struct DataRange {
    uint64_t offset;
    uint64_t len;
  };

  [[nodiscard]] Optional<size_t> findEntry(uint64_t offset) const;
  [[nodiscard]] bool writeEntryRange(
      const Entry& entry,
      const DataRange& range,
      DataWriter writer) const;
  [[nodiscard]] uint64_t countUnacked(uint64_t start, uint64_t end) const;
  [[nodiscard]] uint64_t countOutstanding(uint64_t start, uint64_t end) const;
  void insertOutstandingIntoPending(uint64_t start, uint64_t end);
  void releaseAckedEntries(uint64_t start, uint64_t end);
  void cleanUpEntries();

  CircularDeque<Entry> entries_;
  IntervalSet<uint64_t> ackedIntervals_;
  IntervalSet<uint64_t> abandonedIntervals_;
  IntervalSet<uint64_t> pendingRetransmissions_;
  uint64_t nextUnsentOffset_{0};
  uint64_t tailOffset_{0};
  uint64_t outstandingBytes_{0};
  mutable size_t cachedEntryIndex_{0};
  bool finBuffered_{false};
  bool finSent_{false};
  bool finLost_{false};
  bool finAcked_{false};
  bool writeClosed_{false};
  bool cancelled_{false};
};

} // namespace quic
