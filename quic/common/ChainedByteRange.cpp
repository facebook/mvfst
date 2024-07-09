/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/ChainedByteRange.h>

namespace quic {

[[nodiscard]] bool ChainedByteRange::empty() const {
  if (range_.size() != 0) {
    return false;
  }
  for (auto* current = next_; current != this; current = current->next_) {
    if (current->range_.size() != 0) {
      return false;
    }
  }
  return true;
}

[[nodiscard]] std::string ChainedByteRange::toStr() const {
  std::string result;
  result.reserve(computeChainDataLength());
  result.append(range_.toString());
  for (auto* current = next_; current != this; current = current->next_) {
    result.append(current->range_.toString());
  }
  return result;
}

[[nodiscard]] size_t ChainedByteRange::computeChainDataLength() const {
  size_t fullLength = range_.size();
  for (auto* current = next_; current != this; current = current->next_) {
    fullLength += current->range_.size();
  }
  return fullLength;
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
  head.range_ = *it++;
  chainLength_ += head.range_.size();

  ChainedByteRange* cur = &head;
  for (; it != buf->end(); it++) {
    chainLength_ += it->size();
    auto next = std::make_unique<ChainedByteRange>().release();
    next->range_ = *it;
    next->prev_ = cur;
    cur->next_ = next;
    cur = next;
  }
  cur->next_ = &head;
  head.prev_ = cur;
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
  if (head.range_.empty()) {
    head.range_ = *it;
    chainLength_ += it->size();
    it++;
  }

  ChainedByteRange* tail = head.prev_;
  while (it != buf->end()) {
    if (it->empty()) {
      it++;
      continue;
    }

    auto* newElement = std::make_unique<ChainedByteRange>(*it).release();
    chainLength_ += it->size();
    newElement->next_ = &head;
    newElement->prev_ = tail;

    tail->next_ = newElement;
    tail = newElement;
    head.prev_ = newElement;

    it++;
  }
}

void ChainedByteRangeHead::append(ChainedByteRangeHead&& chainHead) {
  ChainedByteRange* oldTail = head.prev_;
  // Since we're merging the input chain into this one, we need to create a
  // ChainedByteRange for the data that's held as the first buffer in the input
  // chain.
  ChainedByteRange* headSubstitute =
      std::make_unique<ChainedByteRange>(chainHead.head.getRange()).release();
  ChainedByteRange* newTail = (chainHead.head.prev_ == &chainHead.head)
      ? headSubstitute
      : chainHead.head.prev_;

  headSubstitute->next_ =
      (newTail == &chainHead.head) ? headSubstitute : chainHead.head.next_;
  chainHead.head.next_->prev_ = headSubstitute;
  headSubstitute->prev_ = oldTail;
  oldTail->next_ = headSubstitute;
  newTail->next_ = &head;
  head.prev_ = newTail;

  chainLength_ += chainHead.chainLength_;

  chainHead.head.next_ = chainHead.head.prev_ = &chainHead.head;
  chainHead.chainLength_ = 0;
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

  if (head.length() > len) {
    // Just need to trim a little off the head.
    ret.head.range_ =
        folly::ByteRange(head.range_.begin(), head.range_.begin() + len);
    ret.head.next_ = &ret.head;
    ret.head.prev_ = &ret.head;
    head.trimStart(len);
    return ret;
  }

  ChainedByteRange* current = &head;
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
    current = current->next_;
  }

  if (len == 0) {
    /**
     * In this case, we're splitting at the boundary of two ChainedByteRanges.
     * We make head take up the place of the first ChainedByteRange in the
     * second chain.
     */
    ChainedByteRange* tailOfSecondPart =
        (head.prev_ == current) ? &head : head.prev_;
    ChainedByteRange* tailOfFirstPart =
        (current->prev_ == &head ? &ret.head : current->prev_);

    ret.head.range_ = head.range_;
    ret.head.next_ = head.next_;
    ret.head.prev_ = tailOfFirstPart;
    ret.head.next_->prev_ = &ret.head;
    tailOfFirstPart->next_ = &ret.head;

    head.range_ = current->range_;
    head.next_ = current->next_;
    head.prev_ = tailOfSecondPart;
    head.next_->prev_ = &head;
    tailOfSecondPart->next_ = &head;

    delete current;
  } else {
    /**
     * In this case, we're splitting somewhere in the middle of a
     * ChainedByteRange.
     */
    ChainedByteRange* tailOfFirstPart = current;
    ChainedByteRange* tailOfSecondPart =
        (head.prev_ == tailOfFirstPart) ? &head : head.prev_;

    ret.head.range_ = head.range_;

    head.range_ =
        folly::ByteRange(current->range_.begin() + len, current->range_.end());
    current->range_ = folly::ByteRange(
        current->range_.begin(), current->range_.begin() + len);

    ret.head.next_ = head.next_;
    ret.head.prev_ = tailOfFirstPart;
    ret.head.next_->prev_ = &ret.head;

    head.next_ = tailOfFirstPart->next_;
    tailOfFirstPart->next_->prev_ = &head;
    head.prev_ = tailOfSecondPart;

    tailOfFirstPart->next_ = &ret.head;
  }

  return ret;
}

size_t ChainedByteRangeHead::trimStartAtMost(size_t len) {
  size_t amountToSplit = std::min(len, chainLength());
  auto splitRch = splitAtMost(amountToSplit);
  return amountToSplit;
}

void ChainedByteRangeHead::resetChain() {
  ChainedByteRange* curr = head.next_;
  while (curr != &head) {
    auto* next = curr->next_;
    delete curr;
    curr = next;
  }
  head.next_ = &head;
  head.prev_ = &head;
  chainLength_ = 0;
}

void ChainedByteRangeHead::moveChain(ChainedByteRangeHead&& other) {
  head.range_ = other.head.range_;
  ChainedByteRange* headNext = other.head.next_;
  ChainedByteRange* headPrev = other.head.prev_;
  headNext->prev_ = &head;
  headPrev->next_ = &head;
  head.next_ = other.head.next_;
  head.prev_ = other.head.prev_;

  other.head.range_ = folly::ByteRange();
  other.head.next_ = &other.head;
  other.head.prev_ = &other.head;
  chainLength_ = other.chainLength_;
  other.chainLength_ = 0;
}

} // namespace quic
