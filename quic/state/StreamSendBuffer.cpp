/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/StreamSendBuffer.h>

#include <algorithm>
#include <limits>

namespace quic {
namespace {

Optional<uint64_t> rangeEnd(uint64_t offset, uint64_t len) {
  if (len > std::numeric_limits<uint64_t>::max() - offset) {
    return std::nullopt;
  }
  return offset + len;
}

template <typename Func>
void forEachUnackedRange(
    const IntervalSet<uint64_t>& acked,
    uint64_t start,
    uint64_t end,
    Func&& func) {
  auto cursor = start;
  for (const auto& interval : acked) {
    if (interval.end < cursor) {
      continue;
    }
    if (interval.start >= end) {
      break;
    }
    if (cursor < interval.start) {
      const auto unackedEnd = std::min(end, interval.start);
      func(cursor, unackedEnd);
    }
    cursor = std::max(cursor, interval.end + 1);
    if (cursor >= end) {
      return;
    }
  }
  if (cursor < end) {
    func(cursor, end);
  }
}

} // namespace

bool StreamSendBuffer::append(BufPtr data, bool fin) {
  if (writeClosed_ || cancelled_) {
    return false;
  }

  const auto len = data ? data->computeChainDataLength() : 0;
  if (len > kMaxVarInt - tailOffset_) {
    return false;
  }
  if (len > 0) {
    entries_.push_back(
        Entry{.offset = tailOffset_, .len = len, .data = std::move(data)});
    tailOffset_ += len;
  }
  if (fin) {
    finBuffered_ = true;
    writeClosed_ = true;
  }
  return len > 0 || fin;
}

Optional<StreamSendBuffer::SendRange> StreamSendBuffer::nextNewData(
    uint64_t maxLen) const {
  if (cancelled_) {
    return std::nullopt;
  }
  if (nextUnsentOffset_ < tailOffset_) {
    if (maxLen == 0) {
      return std::nullopt;
    }
    const auto len = std::min(maxLen, tailOffset_ - nextUnsentOffset_);
    return SendRange{
        .offset = nextUnsentOffset_,
        .len = len,
        .fin = finBuffered_ && nextUnsentOffset_ + len == tailOffset_};
  }
  if (finBuffered_ && !finSent_) {
    return SendRange{.offset = tailOffset_, .len = 0, .fin = true};
  }
  return std::nullopt;
}

Optional<StreamSendBuffer::SendRange> StreamSendBuffer::nextLoss(
    uint64_t maxLen) const {
  if (cancelled_) {
    return std::nullopt;
  }
  if (!pendingRetransmissions_.empty()) {
    if (maxLen == 0) {
      return std::nullopt;
    }
    const auto& pending = pendingRetransmissions_.front();
    const auto len = std::min(maxLen, pending.end - pending.start + 1);
    return SendRange{
        .offset = pending.start,
        .len = len,
        .fin = finLost_ && pending.start + len == tailOffset_};
  }
  if (finLost_) {
    return SendRange{.offset = tailOffset_, .len = 0, .fin = true};
  }
  return std::nullopt;
}

bool StreamSendBuffer::writeAt(uint64_t offset, uint64_t len, DataWriter writer)
    const {
  const auto end = rangeEnd(offset, len);
  if (!end || *end > tailOffset_ || cancelled_) {
    return false;
  }
  if (len == 0) {
    return true;
  }

  auto entryIndex = findEntry(offset);
  if (!entryIndex) {
    return false;
  }
  auto currentOffset = offset;
  auto remaining = len;
  while (remaining > 0 && *entryIndex < entries_.size()) {
    const auto& entry = entries_[*entryIndex];
    if (!entry.data || currentOffset < entry.offset ||
        currentOffset >= entry.offset + entry.len) {
      return false;
    }
    const auto entryLen =
        std::min(remaining, entry.offset + entry.len - currentOffset);
    if (!writeEntryRange(
            entry,
            DataRange{.offset = currentOffset, .len = entryLen},
            writer)) {
      return false;
    }
    currentOffset += entryLen;
    remaining -= entryLen;
    cachedEntryIndex_ = *entryIndex;
    ++*entryIndex;
    if (remaining > 0 &&
        (*entryIndex >= entries_.size() ||
         entries_[*entryIndex].offset != currentOffset)) {
      return false;
    }
  }
  return remaining == 0;
}

bool StreamSendBuffer::markNewDataSent(const SendRange& range) {
  const auto end = rangeEnd(range.offset, range.len);
  if (!end || cancelled_ || range.offset != nextUnsentOffset_ ||
      *end > tailOffset_ || (range.len == 0 && !range.fin) ||
      (range.fin && (!finBuffered_ || finSent_ || *end != tailOffset_))) {
    return false;
  }

  nextUnsentOffset_ = *end;
  outstandingBytes_ += range.len;
  if (range.fin) {
    finSent_ = true;
  }
  return true;
}

void StreamSendBuffer::markLoss(const SendRange& range) {
  if (cancelled_) {
    return;
  }
  const auto requestedEnd = rangeEnd(range.offset, range.len);
  if (!requestedEnd) {
    return;
  }
  const auto end = std::min(*requestedEnd, nextUnsentOffset_);
  if (range.offset < end) {
    insertUnackedIntoPending(range.offset, end);
  }
  if (range.fin && *requestedEnd == tailOffset_ && finSent_ && !finAcked_) {
    finLost_ = true;
  }
}

void StreamSendBuffer::markRetransmissionSent(const SendRange& range) {
  const auto end = rangeEnd(range.offset, range.len);
  if (!end || cancelled_) {
    return;
  }
  if (range.len > 0) {
    pendingRetransmissions_.withdraw(
        Interval<uint64_t>{range.offset, *end - 1});
  }
  if (range.fin && *end == tailOffset_) {
    finLost_ = false;
  }
}

Optional<StreamSendBuffer::AckResult> StreamSendBuffer::markAcked(
    const SendRange& range) {
  if (cancelled_) {
    return std::nullopt;
  }
  const auto end = rangeEnd(range.offset, range.len);
  if (!end || *end > nextUnsentOffset_ || (range.len == 0 && !range.fin) ||
      (range.fin && (!finSent_ || *end != tailOffset_))) {
    return std::nullopt;
  }

  AckResult result;
  if (range.len > 0) {
    result.newlyAckedBytes = countUnacked(range.offset, *end);
    if (result.newlyAckedBytes > outstandingBytes_) {
      return std::nullopt;
    }
    outstandingBytes_ -= result.newlyAckedBytes;
    ackedIntervals_.insert(range.offset, *end - 1);
    pendingRetransmissions_.withdraw(
        Interval<uint64_t>{range.offset, *end - 1});
    releaseAckedEntries(range.offset, *end);
  }
  if (range.fin) {
    result.newlyAckedFin = !finAcked_;
    finAcked_ = true;
    finLost_ = false;
  }
  return result;
}

bool StreamSendBuffer::truncateFrom(uint64_t offset) {
  if (cancelled_ || offset > tailOffset_) {
    return false;
  }
  if (offset == tailOffset_) {
    return true;
  }

  const auto oldTail = tailOffset_;
  const auto sentEnd = std::min(nextUnsentOffset_, oldTail);
  if (offset < sentEnd) {
    const auto discardedOutstanding = countUnacked(offset, sentEnd);
    if (discardedOutstanding > outstandingBytes_) {
      return false;
    }
    outstandingBytes_ -= discardedOutstanding;
  }
  if (offset < oldTail) {
    const Interval<uint64_t> discarded{offset, oldTail - 1};
    ackedIntervals_.withdraw(discarded);
    pendingRetransmissions_.withdraw(discarded);
  }

  while (!entries_.empty() && entries_.back().offset >= offset) {
    entries_.pop_back();
  }
  if (!entries_.empty() &&
      entries_.back().offset + entries_.back().len > offset) {
    entries_.back().len = offset - entries_.back().offset;
    if (entries_.back().len == 0) {
      entries_.pop_back();
    }
  }

  tailOffset_ = offset;
  nextUnsentOffset_ = std::min(nextUnsentOffset_, offset);
  cachedEntryIndex_ = 0;
  // Truncating before the tail invalidates the FIN at the old final offset.
  finBuffered_ = false;
  finSent_ = false;
  finLost_ = false;
  finAcked_ = false;
  writeClosed_ = true;
  cleanUpEntries();
  return true;
}

void StreamSendBuffer::cancelAll() {
  entries_.clear();
  ackedIntervals_.clear();
  pendingRetransmissions_.clear();
  nextUnsentOffset_ = tailOffset_;
  outstandingBytes_ = 0;
  cachedEntryIndex_ = 0;
  finBuffered_ = false;
  finSent_ = false;
  finLost_ = false;
  finAcked_ = false;
  writeClosed_ = true;
  cancelled_ = true;
}

Optional<size_t> StreamSendBuffer::findEntry(uint64_t offset) const {
  const auto contains = [offset](const Entry& entry) {
    return entry.offset <= offset && offset < entry.offset + entry.len;
  };
  if (cachedEntryIndex_ < entries_.size() &&
      contains(entries_[cachedEntryIndex_])) {
    return cachedEntryIndex_;
  }
  if (cachedEntryIndex_ + 1 < entries_.size() &&
      contains(entries_[cachedEntryIndex_ + 1])) {
    ++cachedEntryIndex_;
    return cachedEntryIndex_;
  }

  const auto it =
      std::ranges::upper_bound(entries_, offset, {}, [](const Entry& entry) {
        return entry.offset + entry.len;
      });
  if (it == entries_.end() || !contains(*it)) {
    return std::nullopt;
  }
  cachedEntryIndex_ = static_cast<size_t>(it - entries_.begin());
  return cachedEntryIndex_;
}

bool StreamSendBuffer::writeEntryRange(
    const Entry& entry,
    const DataRange& range,
    DataWriter writer) const {
  if (!entry.data) {
    return false;
  }
  auto skip = range.offset - entry.offset;
  auto remaining = range.len;
  auto logicalRemaining = entry.len;
  for (const auto& current : *entry.data) {
    const auto segmentLen =
        std::min<uint64_t>(current.size(), logicalRemaining);
    if (skip >= segmentLen) {
      skip -= segmentLen;
    } else {
      const auto writeLen = std::min(remaining, segmentLen - skip);
      if (!writer(
              ByteRange{
                  current.data() + skip, static_cast<size_t>(writeLen)})) {
        return false;
      }
      remaining -= writeLen;
      skip = 0;
      if (remaining == 0) {
        return true;
      }
    }
    logicalRemaining -= segmentLen;
    if (logicalRemaining == 0) {
      break;
    }
  }
  return false;
}

uint64_t StreamSendBuffer::countUnacked(uint64_t start, uint64_t end) const {
  uint64_t count = 0;
  forEachUnackedRange(
      ackedIntervals_, start, end, [&count](uint64_t begin, uint64_t finish) {
        count += finish - begin;
      });
  return count;
}

void StreamSendBuffer::insertUnackedIntoPending(uint64_t start, uint64_t end) {
  forEachUnackedRange(
      ackedIntervals_, start, end, [this](uint64_t begin, uint64_t finish) {
        pendingRetransmissions_.insert(begin, finish - 1);
      });
}

void StreamSendBuffer::releaseAckedEntries(uint64_t start, uint64_t end) {
  if (entries_.empty() || entries_.front().offset >= end) {
    cleanUpEntries();
    return;
  }
  start = std::max(start, entries_.front().offset);
  auto entryIndex = findEntry(start);
  if (!entryIndex) {
    cleanUpEntries();
    return;
  }
  while (*entryIndex < entries_.size()) {
    auto& entry = entries_[*entryIndex];
    if (entry.offset >= end) {
      break;
    }
    if (entry.data &&
        ackedIntervals_.contains(entry.offset, entry.offset + entry.len - 1)) {
      // Keep the offset metadata until earlier entries can also be removed.
      entry.data.reset();
    }
    ++*entryIndex;
  }
  cleanUpEntries();
}

void StreamSendBuffer::cleanUpEntries() {
  while (!entries_.empty() && !entries_.front().data) {
    entries_.pop_front();
  }
  cachedEntryIndex_ = 0;
}

} // namespace quic
