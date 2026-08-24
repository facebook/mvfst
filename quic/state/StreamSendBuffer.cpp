/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/StreamSendBuffer.h>

#include <algorithm>
#include <array>
#include <limits>

namespace quic {
namespace {

Optional<uint64_t> rangeEnd(uint64_t offset, uint64_t len) {
  if (len > std::numeric_limits<uint64_t>::max() - offset) {
    return std::nullopt;
  }
  return offset + len;
}

template <size_t N, typename Func>
void forEachCoveredRange(
    const std::array<const IntervalSet<uint64_t>*, N>& coveredSets,
    uint64_t start,
    uint64_t end,
    Func func) {
  using Iterator = IntervalSet<uint64_t>::const_iterator;
  std::array<Iterator, N> iterators;
  std::array<Iterator, N> ends;
  for (size_t i = 0; i < N; ++i) {
    iterators[i] = std::ranges::lower_bound(
        *coveredSets[i], start, {}, [](const auto& interval) {
          return interval.end;
        });
    ends[i] = coveredSets[i]->end();
  }

  Optional<uint64_t> coveredStart;
  uint64_t coveredEnd = 0;
  while (true) {
    size_t nextSet = N;
    for (size_t i = 0; i < N; ++i) {
      if (iterators[i] != ends[i] &&
          (nextSet == N || iterators[i]->start < iterators[nextSet]->start)) {
        nextSet = i;
      }
    }
    if (nextSet == N || iterators[nextSet]->start >= end) {
      break;
    }

    const auto& interval = *iterators[nextSet]++;
    const auto intervalStart = std::max(start, interval.start);
    const auto intervalEnd = std::min(end, interval.end + 1);
    if (!coveredStart) {
      coveredStart = intervalStart;
      coveredEnd = intervalEnd;
    } else if (intervalStart <= coveredEnd) {
      coveredEnd = std::max(coveredEnd, intervalEnd);
    } else {
      func(*coveredStart, coveredEnd);
      coveredStart = intervalStart;
      coveredEnd = intervalEnd;
    }
  }
  if (coveredStart) {
    func(*coveredStart, coveredEnd);
  }
}

template <size_t N, typename Func>
void forEachUncoveredRange(
    const std::array<const IntervalSet<uint64_t>*, N>& coveredSets,
    uint64_t start,
    uint64_t end,
    Func func) {
  auto cursor = start;
  forEachCoveredRange(
      coveredSets,
      start,
      end,
      [&cursor, &func](uint64_t coveredStart, uint64_t coveredEnd) {
        if (cursor < coveredStart) {
          func(cursor, coveredStart);
        }
        cursor = std::max(cursor, coveredEnd);
      });
  if (cursor < end) {
    func(cursor, end);
  }
}

} // namespace

bool StreamSendBuffer::append(BufPtr data, bool fin) {
  const auto len = data ? data->computeChainDataLength() : 0;
  if (!canAppend(len)) {
    return false;
  }
  auto entryOffset = tailOffset_;
  while (data) {
    auto next = data->pop();
    const auto entryLen = data->length();
    if (entryLen > 0) {
      entries_.push_back(
          Entry{
              .offset = entryOffset, .len = entryLen, .data = std::move(data)});
      entryOffset += entryLen;
    }
    data = std::move(next);
  }
  tailOffset_ += len;
  if (fin) {
    finBuffered_ = true;
    writeClosed_ = true;
  }
  return true;
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
  return nextLossAfter(0, true, maxLen);
}

Optional<StreamSendBuffer::SendRange> StreamSendBuffer::nextLossAfter(
    uint64_t minOffset,
    bool includeFin,
    uint64_t maxLen) const {
  if (cancelled_) {
    return std::nullopt;
  }
  const auto pending = std::ranges::lower_bound(
      pendingRetransmissions_, minOffset, {}, [](const auto& interval) {
        return interval.end;
      });
  if (pending != pendingRetransmissions_.end()) {
    if (maxLen == 0) {
      return std::nullopt;
    }
    const auto offset = std::max(minOffset, pending->start);
    const auto len = std::min(maxLen, pending->end - offset + 1);
    return SendRange{
        .offset = offset,
        .len = len,
        .fin = includeFin && finLost_ && offset + len == tailOffset_};
  }
  if (includeFin && finLost_ && minOffset <= tailOffset_) {
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

bool StreamSendBuffer::isOutstanding(const SendRange& range) const {
  const auto end = rangeEnd(range.offset, range.len);
  if (!end || cancelled_ || *end > nextUnsentOffset_ ||
      (range.len == 0 && !range.fin) ||
      countOutstanding(range.offset, *end) != range.len) {
    return false;
  }
  return !range.fin ||
      (finSent_ && !finAcked_ && !finAbandoned_ && *end == tailOffset_);
}

std::optional<StreamSendBuffer::SendRange> StreamSendBuffer::firstOutstandingIn(
    const SendRange& range,
    uint64_t maxLen) const {
  const auto end = rangeEnd(range.offset, range.len);
  if (!end || cancelled_ || *end > nextUnsentOffset_) {
    return std::nullopt;
  }

  auto acked = std::ranges::lower_bound(
      ackedIntervals_, range.offset, {}, [](const auto& interval) {
        return interval.end;
      });
  auto abandoned = std::ranges::lower_bound(
      abandonedIntervals_, range.offset, {}, [](const auto& interval) {
        return interval.end;
      });
  auto cursor = range.offset;
  while (cursor < *end) {
    auto outstandingEnd = *end;
    bool cursorRetired = false;
    const auto inspectRetired = [&](auto& interval, const auto intervalEnd) {
      while (interval != intervalEnd && interval->end < cursor) {
        ++interval;
      }
      if (interval != intervalEnd) {
        if (interval->start <= cursor) {
          cursor = interval->end + 1;
          cursorRetired = true;
        } else {
          outstandingEnd = std::min(outstandingEnd, interval->start);
        }
      }
    };
    inspectRetired(acked, ackedIntervals_.end());
    inspectRetired(abandoned, abandonedIntervals_.end());
    if (cursorRetired) {
      continue;
    }
    if (maxLen == 0) {
      return std::nullopt;
    }
    const auto selectedLen = std::min(maxLen, outstandingEnd - cursor);
    const auto selectedEnd = cursor + selectedLen;
    return SendRange{
        .offset = cursor,
        .len = selectedEnd - cursor,
        .fin = range.fin && *end == tailOffset_ && selectedEnd == *end &&
            finSent_ && !finAcked_ && !finAbandoned_};
  }

  if (range.fin && *end == tailOffset_ && finSent_ && !finAcked_ &&
      !finAbandoned_) {
    return SendRange{.offset = *end, .len = 0, .fin = true};
  }
  return std::nullopt;
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

bool StreamSendBuffer::markLoss(const SendRange& range) {
  if (cancelled_) {
    return false;
  }
  const auto requestedEnd = rangeEnd(range.offset, range.len);
  if (!requestedEnd) {
    return false;
  }
  bool addedLoss = false;
  const auto end = std::min(*requestedEnd, nextUnsentOffset_);
  if (range.offset < end) {
    addedLoss = countNewLoss(range.offset, end) > 0;
    insertOutstandingIntoPending(range.offset, end);
  }
  if (range.fin && *requestedEnd == tailOffset_ && finSent_ && !finAcked_ &&
      !finAbandoned_) {
    addedLoss = addedLoss || !finLost_;
    finLost_ = true;
  }
  return addedLoss;
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

Optional<bool> StreamSendBuffer::abandon(const SendRange& range) {
  if (cancelled_) {
    return false;
  }
  const auto requestedEnd = rangeEnd(range.offset, range.len);
  if (!requestedEnd) {
    return std::nullopt;
  }
  bool retired = false;
  const auto end = std::min(*requestedEnd, nextUnsentOffset_);
  if (range.offset < end) {
    const auto retiredOutstanding = countOutstanding(range.offset, end);
    if (retiredOutstanding > outstandingBytes_) {
      return std::nullopt;
    }
    retired = retiredOutstanding > 0;
    outstandingBytes_ -= retiredOutstanding;
    abandonedIntervals_.insert(range.offset, end - 1);
    pendingRetransmissions_.withdraw(Interval<uint64_t>{range.offset, end - 1});
    releaseRetiredEntries(range.offset, end);
  }
  if (range.fin && *requestedEnd == tailOffset_ && finSent_ && !finAcked_) {
    retired = retired || !finAbandoned_;
    finAbandoned_ = true;
    finLost_ = false;
  }
  return retired;
}

Optional<StreamSendBuffer::AckResult> StreamSendBuffer::markAcked(
    const SendRange& range) {
  if (cancelled_) {
    return AckResult{};
  }
  const auto end = rangeEnd(range.offset, range.len);
  if (!end || *end > nextUnsentOffset_ || (range.len == 0 && !range.fin) ||
      (range.fin && (!finSent_ || *end != tailOffset_))) {
    return std::nullopt;
  }

  AckResult result;
  if (range.len > 0) {
    const auto newlyRetiredOutstanding = countOutstanding(range.offset, *end);
    if (newlyRetiredOutstanding > outstandingBytes_) {
      return std::nullopt;
    }
    result.newlyAckedBytes = newlyRetiredOutstanding;
    outstandingBytes_ -= newlyRetiredOutstanding;
  }
  if (range.len > 0 || range.fin) {
    ackedIntervals_.insert(range.offset, range.fin ? *end : *end - 1);
  }
  if (range.len > 0) {
    pendingRetransmissions_.withdraw(
        Interval<uint64_t>{range.offset, *end - 1});
    releaseRetiredEntries(range.offset, *end);
  }
  if (range.fin) {
    result.newlyAckedFin = !finAcked_;
    finAcked_ = true;
    finLost_ = false;
    finAbandoned_ = false;
  }
  return result;
}

bool StreamSendBuffer::allBytesAckedTill(uint64_t offset) const {
  return !ackedIntervals_.empty() && ackedIntervals_.front().start == 0 &&
      ackedIntervals_.front().end >= offset;
}

Optional<uint64_t> StreamSendBuffer::largestDeliverableOffset() const {
  if (ackedIntervals_.empty() || ackedIntervals_.front().start != 0) {
    return std::nullopt;
  }
  return ackedIntervals_.front().end;
}

bool StreamSendBuffer::truncateFrom(uint64_t offset) {
  if (cancelled_ || offset > tailOffset_) {
    return false;
  }
  if (offset == tailOffset_) {
    return true;
  }

  const auto oldTail = tailOffset_;
  const bool finWasSent = finSent_;
  const bool finWasAcked = finAcked_;
  const auto sentEnd = std::min(nextUnsentOffset_, oldTail);
  if (offset < sentEnd) {
    const auto discardedOutstanding = countOutstanding(offset, sentEnd);
    if (discardedOutstanding > outstandingBytes_) {
      return false;
    }
    outstandingBytes_ -= discardedOutstanding;
    abandonedIntervals_.insert(offset, sentEnd - 1);
  }
  const Interval<uint64_t> discarded{offset, oldTail - 1};
  pendingRetransmissions_.withdraw(discarded);

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

  tailOffset_ = std::max(offset, nextUnsentOffset_);
  cachedEntryIndex_ = 0;
  // Truncation drops buffered FIN intent but preserves transmitted FIN state.
  finBuffered_ = false;
  finSent_ = finWasSent;
  finLost_ = false;
  finAcked_ = finWasAcked;
  finAbandoned_ = finWasSent && !finWasAcked;
  writeClosed_ = true;
  cleanUpEntries();
  return true;
}

void StreamSendBuffer::cancelAll() {
  entries_.clear();
  ackedIntervals_.clear();
  abandonedIntervals_.clear();
  pendingRetransmissions_.clear();
  tailOffset_ = nextUnsentOffset_;
  outstandingBytes_ = 0;
  cachedEntryIndex_ = 0;
  finBuffered_ = false;
  finSent_ = false;
  finLost_ = false;
  finAcked_ = false;
  finAbandoned_ = false;
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
  forEachUncoveredRange(
      std::array{&ackedIntervals_},
      start,
      end,
      [&count](uint64_t begin, uint64_t finish) { count += finish - begin; });
  return count;
}

uint64_t StreamSendBuffer::countOutstanding(uint64_t start, uint64_t end)
    const {
  uint64_t count = 0;
  forEachUncoveredRange(
      std::array<const IntervalSet<uint64_t>*, 2>{
          &ackedIntervals_, &abandonedIntervals_},
      start,
      end,
      [&count](uint64_t begin, uint64_t finish) { count += finish - begin; });
  return count;
}

uint64_t StreamSendBuffer::countNewLoss(uint64_t start, uint64_t end) const {
  uint64_t count = 0;
  forEachUncoveredRange(
      std::array{
          &ackedIntervals_, &abandonedIntervals_, &pendingRetransmissions_},
      start,
      end,
      [&count](uint64_t begin, uint64_t finish) { count += finish - begin; });
  return count;
}

void StreamSendBuffer::insertOutstandingIntoPending(
    uint64_t start,
    uint64_t end) {
  forEachUncoveredRange(
      std::array<const IntervalSet<uint64_t>*, 2>{
          &ackedIntervals_, &abandonedIntervals_},
      start,
      end,
      [this](uint64_t begin, uint64_t finish) {
        pendingRetransmissions_.insert(begin, finish - 1);
      });
}

void StreamSendBuffer::releaseRetiredEntries(uint64_t start, uint64_t end) {
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
  const auto scanStart = entries_[*entryIndex].offset;
  auto scanEnd = scanStart;
  for (auto i = *entryIndex; i < entries_.size() && entries_[i].offset < end;
       ++i) {
    scanEnd = std::max(scanEnd, entries_[i].offset + entries_[i].len);
  }
  forEachCoveredRange(
      std::array<const IntervalSet<uint64_t>*, 2>{
          &ackedIntervals_, &abandonedIntervals_},
      scanStart,
      scanEnd,
      [this, &entryIndex](uint64_t retiredStart, uint64_t retiredEnd) {
        while (*entryIndex < entries_.size() &&
               entries_[*entryIndex].offset + entries_[*entryIndex].len <=
                   retiredStart) {
          ++*entryIndex;
        }
        while (*entryIndex < entries_.size()) {
          auto& entry = entries_[*entryIndex];
          if (entry.offset >= retiredEnd) {
            break;
          }
          if (entry.offset >= retiredStart &&
              entry.offset + entry.len <= retiredEnd) {
            // Keep the offset metadata until earlier entries can also be
            // removed.
            entry.data.reset();
          }
          ++*entryIndex;
        }
      });
  cleanUpEntries();
}

void StreamSendBuffer::cleanUpEntries() {
  while (!entries_.empty() && !entries_.front().data) {
    entries_.pop_front();
  }
  cachedEntryIndex_ = 0;
}

} // namespace quic
