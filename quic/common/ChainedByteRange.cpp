/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/ChainedByteRange.h>

namespace quic {

[[nodiscard]] std::string ChainedByteRangeHead::toStr() const {
  std::string result;
  result.reserve(chainLength_);
  result.append(head_.range_.toString());
  for (auto* current = head_.next_; current; current = current->next_) {
    result.append(current->range_.toString());
  }
  return result;
}

ChainedByteRangeHead::ChainedByteRangeHead(const Buf& buf) {
  if (!buf || buf->empty()) {
    return;
  }

  auto it = buf->begin();
  while (it != buf->end() && it->empty()) {
    it++;
  }

  CHECK(it != buf->end());
  head_.range_ = *it++;
  chainLength_ += head_.range_.size();

  ChainedByteRange* cur = &head_;
  for (; it != buf->end(); it++) {
    chainLength_ += it->size();
    auto next = std::make_unique<ChainedByteRange>().release();
    next->range_ = *it;
    cur->next_ = next;
    cur = next;
  }
  tail_ = cur;
}

ChainedByteRangeHead::ChainedByteRangeHead(
    ChainedByteRangeHead&& other) noexcept {
  moveChain(std::move(other));
}

ChainedByteRangeHead& ChainedByteRangeHead::operator=(
    ChainedByteRangeHead&& other) noexcept {
  moveChain(std::move(other));
  return *this;
}

ChainedByteRangeHead::~ChainedByteRangeHead() {
  resetChain();
}

void ChainedByteRangeHead::append(const Buf& buf) {
  if (!buf || buf->empty()) {
    return;
  }

  auto it = buf->begin();
  while (it != buf->end() && it->empty()) {
    it++;
  }

  CHECK(it != buf->end());
  // We know that *it is non-empty at this point because of the initial
  // check that the chain is non-empty.
  if (head_.range_.empty()) {
    head_.range_ = *it;
    chainLength_ += it->size();
    it++;
  }

  while (it != buf->end()) {
    if (it->empty()) {
      it++;
      continue;
    }

    auto* newElement = std::make_unique<ChainedByteRange>(*it).release();
    chainLength_ += it->size();

    tail_->next_ = newElement;
    tail_ = newElement;

    it++;
  }
}

void ChainedByteRangeHead::append(ChainedByteRangeHead&& chainHead) {
  ChainedByteRange* otherHead =
      std::make_unique<ChainedByteRange>(chainHead.head_.getRange()).release();
  bool chainHeadIsChained = chainHead.isChained();

  tail_->next_ = otherHead;
  otherHead->next_ = chainHead.head_.next_;
  tail_ = (chainHeadIsChained ? chainHead.tail_ : otherHead);

  chainLength_ += chainHead.chainLength_;

  chainHead.head_.next_ = nullptr;
  chainHead.chainLength_ = 0;
  chainHead.tail_ = &chainHead.head_;
}

ChainedByteRangeHead ChainedByteRangeHead::splitAtMost(size_t len) {
  // entire chain requested
  if (len >= chainLength_) {
    return std::move(*this);
  }

  ChainedByteRangeHead ret;
  ret.chainLength_ = len;
  if (len == 0) {
    return ret;
  }

  chainLength_ -= len;

  if (head_.length() > len) {
    // Just need to trim a little off the head.
    ret.head_.range_ =
        folly::ByteRange(head_.range_.begin(), head_.range_.begin() + len);
    ret.head_.next_ = nullptr;
    ret.tail_ = &ret.head_;
    head_.trimStart(len);
    return ret;
  }

  ChainedByteRange* current = &head_;
  ChainedByteRange* previousToCurrent = current;
  /**
   * Find the last ChainedByteRange containing range requested. This will
   * definitively terminate without looping back to head since we know length >
   * len.
   */
  while (len != 0) {
    if (current->length() > len) {
      break;
    }
    len -= current->length();
    if (current != previousToCurrent) {
      previousToCurrent = previousToCurrent->next_;
    }
    current = current->next_;
  }

  if (len == 0) {
    /**
     * In this case, we're splitting at the boundary of two ChainedByteRanges.
     * We make head take up the place of the first ChainedByteRange in the
     * second chain.
     */
    ret.head_.range_ = head_.range_;
    head_.range_ = current->range_;

    if (previousToCurrent == &head_) {
      // No modifications to ret, since it's going to be the only member in
      // the chain.
      head_.next_ = current->next_;
    } else {
      ret.head_.next_ = head_.next_;
      ret.tail_ = previousToCurrent;
      previousToCurrent->next_ = nullptr;
      head_.next_ = current->next_;
    }

    if (tail_ == current) {
      tail_ = &head_;
    }

    delete current;
  } else {
    /**
     * In this case, we're splitting somewhere in the middle of a
     * ChainedByteRange.
     */
    ret.head_.range_ = head_.range_;
    head_.range_ =
        folly::ByteRange(current->range_.begin() + len, current->range_.end());
    current->range_ = folly::ByteRange(
        current->range_.begin(), current->range_.begin() + len);

    ret.head_.next_ = head_.next_;
    ret.tail_ = current;

    if (current == tail_) {
      head_.next_ = nullptr;
      tail_ = &head_;
    } else {
      head_.next_ = current->next_;
    }

    ret.tail_->next_ = nullptr;
  }

  return ret;
}

size_t ChainedByteRangeHead::trimStartAtMost(size_t len) {
  size_t amountToSplit = std::min(len, chainLength());
  auto splitRch = splitAtMost(amountToSplit);
  return amountToSplit;
}

void ChainedByteRangeHead::resetChain() {
  ChainedByteRange* curr = head_.next_;
  while (curr) {
    auto* next = curr->next_;
    delete curr;
    curr = next;
  }
  head_.next_ = nullptr;
  tail_ = &head_;
  chainLength_ = 0;
  head_.range_.clear();
}

void ChainedByteRangeHead::moveChain(ChainedByteRangeHead&& other) {
  auto* prevTail = tail_;
  tail_ = other.isChained() ? other.tail_ : &head_;
  other.tail_ = isChained() ? prevTail : &other.head_;

  std::swap(head_.range_, other.head_.range_);
  std::swap(head_.next_, other.head_.next_);
  std::swap(chainLength_, other.chainLength_);
}

} // namespace quic
