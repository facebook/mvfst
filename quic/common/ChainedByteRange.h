/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <folly/Range.h>
#include <quic/QuicConstants.h>

namespace quic {

/*
 * The ChainedByteRange depicts one block of contiguous
 * memory, and has a next_ and a prev_ pointer. It has APIs
 * that can be used to trim the start or end of this specific
 * contiguous memory block.
 */
class ChainedByteRange {
 public:
  ChainedByteRange() : next_(this), prev_(this) {}

  explicit ChainedByteRange(folly::ByteRange range)
      : range_(range), next_(this), prev_(this) {}

  /**
   * Returns the length only of this ChainedByteRange
   */
  [[nodiscard]] size_t length() const {
    return range_.size();
  }

  /**
   * Check whether the entire chain is empty
   */
  [[nodiscard]] bool empty() const;

  [[nodiscard]] std::string toStr() const;

  [[nodiscard]] size_t computeChainDataLength() const;

  /**
   * Trim the start of this specific contiguous memory block
   */
  void trimStart(size_t n) {
    n = std::min(n, range_.size());
    range_.advance(n);
  }

  [[nodiscard]] folly::ByteRange getRange() const {
    return range_;
  }

  [[nodiscard]] ChainedByteRange* getNext() const {
    return next_;
  }

  [[nodiscard]] ChainedByteRange* getPrev() const {
    return prev_;
  }

 private:
  folly::ByteRange range_;
  ChainedByteRange* next_{nullptr};
  ChainedByteRange* prev_{nullptr};

  friend class ChainedByteRangeHead;
};

/*
 * The ChainedByteRangeHead depicts the head of a chain of ChainedByteRanges.
 * It caches the length of the total chain, which is useful in many cases
 * because we don't want to walk the entire chain to get the length.
 * Additionally, it allows us to trim or split off multiple ChainedByteRanges
 * with the splitAtMost and trimStartAtMost APIs.
 */
class ChainedByteRangeHead {
 public:
  ChainedByteRange head;

  explicit ChainedByteRangeHead(const Buf& buf);

  ChainedByteRangeHead() = default;

  ChainedByteRangeHead(ChainedByteRangeHead&& other) noexcept {
    moveChain(std::move(other));
  }

  ChainedByteRangeHead& operator=(ChainedByteRangeHead&& other) noexcept {
    resetChain();
    moveChain(std::move(other));
    return *this;
  }

  ~ChainedByteRangeHead() {
    resetChain();
  }

  [[nodiscard]] bool empty() const {
    return chainLength_ == 0;
  }

  [[nodiscard]] size_t chainLength() const {
    return chainLength_;
  }

  /**
   * Splits off the initial n bytes from the chain and returns them.
   */
  ChainedByteRangeHead splitAtMost(size_t n);

  size_t trimStartAtMost(size_t len);

  void append(const Buf& buf);

  void append(ChainedByteRangeHead&& chainHead);

 private:
  void resetChain();

  void moveChain(ChainedByteRangeHead&& other);

  size_t chainLength_{0};
};

} // namespace quic
