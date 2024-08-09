/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>

namespace quic {

/*
 * We use the BufAccessor in order to access a section of contiguous memory.
 * Right now, it works on an unchained IOBuf under the hood, but the plan is
 * to change it to have a uint8_t* under the hood. Once that's done, we can
 * remove the IOBuf-specific APIs, namely buf(), obtain(), and release().
 */
class BufAccessor {
 public:
  explicit BufAccessor(Buf buf);

  // The result capacity could be higher than the desired capacity.
  explicit BufAccessor(size_t capacity);

  ~BufAccessor() = default;

  // API will be removed once we make the BufAccessor work on a uint8_t* instead
  // of an IOBuf.
  Buf& buf();

  // API will be removed once we make the BufAccessor work on a uint8_t* instead
  // of an IOBuf.
  Buf obtain();

  /**
   * Caller releases the IOBuf back to the accessor to own. The capacity has to
   * match the original IOBuf. API will be removed once we make the BufAccessor
   * work on a uint8_t* instead of an IOBuf.
   */
  void release(Buf buf);

  /**
   * Returns whether the BufAccessor currently owns an IOBuf.
   */
  bool ownsBuffer() const;

  // Mirrored APIs from IOBuf.h
  const uint8_t* tail() const;
  const uint8_t* data() const;
  std::size_t tailroom() const;
  std::size_t headroom() const;

  std::size_t length() const;

  void clear();

  bool isChained() const;

  void trimEnd(std::size_t amount);

  void trimStart(std::size_t amount);

  uint8_t* writableTail();

  void append(std::size_t amount);

 private:
  Buf buf_;
  size_t capacity_;
};
} // namespace quic
