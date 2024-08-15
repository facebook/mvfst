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
 * The ChainedByteRangeHead depicts the head of a chain of ChainedByteRanges.
 * It caches the length of the total chain, which is useful in many cases
 * because we don't want to walk the entire chain to get the length.
 * Additionally, it allows us to trim or split off multiple ChainedByteRanges
 * with the splitAtMost and trimStartAtMost APIs.
 */
class ChainedByteRangeHead {
 private:
  /*
   * The ChainedByteRange depicts one block of contiguous
   * memory, and has a next_ pointer. It has APIs
   * that can be used to trim the start or end of this specific
   * contiguous memory block.
   */
  class ChainedByteRange {
   public:
    ChainedByteRange() = default;

    explicit ChainedByteRange(folly::ByteRange range) : range_(range) {}

    /**
     * Returns the length only of this ChainedByteRange
     */
    [[nodiscard]] size_t length() const {
      return range_.size();
    }

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

   private:
    folly::ByteRange range_;
    ChainedByteRange* next_{nullptr};
    friend class ChainedByteRangeHead;
  };

 public:
  explicit ChainedByteRangeHead(const Buf& buf);

  ChainedByteRangeHead() = default;

  ChainedByteRangeHead(ChainedByteRangeHead&& other) noexcept;

  ChainedByteRangeHead& operator=(ChainedByteRangeHead&& other) noexcept;

  ~ChainedByteRangeHead();

  bool isChained() const {
    return head_.next_ != nullptr;
  }

  [[nodiscard]] bool empty() const {
    return chainLength_ == 0;
  }

  [[nodiscard]] size_t chainLength() const {
    return chainLength_;
  }

  [[nodiscard]] std::string toStr() const;

  /**
   * Splits off the initial n bytes from the chain and returns them.
   */
  ChainedByteRangeHead splitAtMost(size_t n);

  size_t trimStartAtMost(size_t len);

  void append(const Buf& buf);

  void append(ChainedByteRangeHead&& chainHead);

  const ChainedByteRange* getHead() const {
    return &head_;
  }

 private:
  void resetChain();

  void moveChain(ChainedByteRangeHead&& other);

  ChainedByteRange head_;

  size_t chainLength_{0};

  ChainedByteRange* tail_{&head_};
};

} // namespace quic
