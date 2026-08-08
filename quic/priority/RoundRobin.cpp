/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/logging/oops_logger/OopsLogger.h>
#include <quic/priority/RoundRobin.h>

#include <algorithm>

namespace {
static constexpr size_t kBuildIndexThreshold = 30;
static constexpr size_t kDestroyIndexThreshold = 10;
} // namespace

namespace quic {

RoundRobin::RoundRobin(RoundRobin&& other) noexcept {
  *this = std::move(other);
}

RoundRobin& RoundRobin::operator=(RoundRobin&& other) noexcept {
  if (this == &other) {
    return *this;
  }
  // Sample this before the move: afterwards other.list_ is empty and the
  // comparison would answer for the wrong container.
  const bool onEnd = other.nextIt_ == other.list_.end();
  list_ = std::move(other.list_);
  indexMap_ = std::move(other.indexMap_);
  advanceType_ = other.advanceType_;
  useIndexMap_ = other.useIndexMap_;
  advanceAfter_ = other.advanceAfter_;
  current_ = other.current_;
  // Iterators to elements survived the move and now name nodes in list_.
  nextIt_ = onEnd ? list_.end() : other.nextIt_;
  other.nextIt_ = other.list_.end();
  other.current_ = 0;
  other.useIndexMap_ = false;
  return *this;
}

void RoundRobin::advanceAfterNext(size_t n) {
  if (advanceType_ == AdvanceType::Bytes) {
    current_ = 0;
  }
  advanceType_ = AdvanceType::Nexts;
  advanceAfter_ = n;
}

void RoundRobin::advanceAfterBytes(uint64_t bytes) {
  if (advanceType_ == AdvanceType::Nexts) {
    current_ = 0;
  }
  advanceType_ = AdvanceType::Bytes;
  advanceAfter_ = bytes;
}

bool RoundRobin::empty() const {
  return list_.empty();
}

// The caller needs to verify it never inserts a duplicate
void RoundRobin::insert(quic::PriorityQueue::Identifier value) {
  MVDCHECK(!erase(value), "Duplicate value");
  // Insert new integer at the tail of the list
  if (!useIndexMap_ && list_.size() >= kBuildIndexThreshold) {
    useIndexMap_ = true;
    buildIndex();
  }
  auto insertIt = list_.insert(nextIt_, value);
  if (list_.size() == 1) {
    nextIt_ = list_.begin();
  }
  if (useIndexMap_) {
    indexMap_[value] = insertIt;
  }
}

bool RoundRobin::erase(quic::PriorityQueue::Identifier value) {
  if (list_.empty()) {
    return false;
  }
  if (useIndexMap_) {
    auto it = indexMap_.find(value);
    if (it == indexMap_.end()) {
      return false;
    }
    auto listIt = it->second;
    indexMap_.erase(it);
    erase(listIt);
    return true;
  } else {
    // the most likely erase is from next or next - 1
    if (*nextIt_ == value) {
      erase(nextIt_);
      return true;
    }

    // Search backwards from nextIt_ - 1 to the beginning
    auto reverseIt = std::make_reverse_iterator(nextIt_);
    auto rpos = std::find(reverseIt, list_.rend(), value);
    if (rpos != list_.rend()) {
      erase(std::prev(rpos.base()));
      return true;
    }
    // Search forwards from nextIt_ + 1 to the end
    auto pos = std::find(std::next(nextIt_), list_.end(), value);
    if (pos != list_.end()) {
      erase(pos);
      return true;
    }
    return false;
  }
}

quic::PriorityQueue::Identifier RoundRobin::getNext(
    const quic::Optional<uint64_t>& bytes) {
  PROTO_OOPS_LOG_IF(
      list_.empty(),
      proto_oops::getThreadLocalOopsLogger(),
      "quic_round_robin_priority_queue",
      "invariant_violation: priority queue getNext called on empty queue");
  MVCHECK(!list_.empty());
  auto ret = *nextIt_;
  consume(bytes);
  return ret;
}

[[nodiscard]] quic::PriorityQueue::Identifier RoundRobin::peekNext() const {
  PROTO_OOPS_LOG_IF(
      list_.empty(),
      proto_oops::getThreadLocalOopsLogger(),
      "quic_round_robin_priority_queue",
      "invariant_violation: priority queue peekNext called on empty queue");
  MVCHECK(!list_.empty());
  return *nextIt_;
}

void RoundRobin::consume(const quic::Optional<uint64_t>& bytes) {
  if (advanceType_ == AdvanceType::Bytes) {
    current_ += bytes.value_or(0);
  } else {
    current_++;
  }
  maybeAdvance();
}

void RoundRobin::clear() {
  list_.clear();
  if (useIndexMap_) {
    indexMap_.clear();
    useIndexMap_ = false;
  }
  nextIt_ = list_.end();
  current_ = 0;
}

void RoundRobin::erase(ListType::iterator eraseIt) {
  if (eraseIt == nextIt_) {
    nextIt_ = list_.erase(eraseIt);
    if (nextIt_ == list_.end()) {
      nextIt_ = list_.begin();
    }
    // The turn belonged to the erased element, so the next one starts fresh.
    current_ = 0;
  } else {
    list_.erase(eraseIt);
  }
  if (list_.size() < kDestroyIndexThreshold) {
    useIndexMap_ = false;
    indexMap_.clear();
  }
}

void RoundRobin::maybeAdvance() {
  PROTO_OOPS_LOG_IF(
      list_.empty(),
      proto_oops::getThreadLocalOopsLogger(),
      "quic_round_robin_priority_queue",
      "invariant_violation: priority queue advanced while empty");
  MVCHECK(!list_.empty());
  if (current_ >= advanceAfter_) {
    ++nextIt_;
    current_ = 0;
    if (nextIt_ == list_.end()) {
      nextIt_ = list_.begin();
    }
  }
}

void RoundRobin::buildIndex() {
  for (auto it = list_.begin(); it != list_.end(); ++it) {
    indexMap_[*it] = it;
  }
}

} // namespace quic
