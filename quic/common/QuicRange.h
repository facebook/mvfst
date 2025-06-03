/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

namespace quic {
template <class Iter>
struct Range {
  Iter begin_;
  Iter end_;

  Range(Iter begin, size_t size) : begin_(begin), end_(begin + size) {}

  Range(Iter begin, Iter end) : begin_(begin), end_(end) {}

  Range() : begin_(nullptr), end_(nullptr) {}

  size_t size() const {
    return end_ - begin_;
  }

  void advance(size_t amount) {
    begin_ += amount;
  }

  bool empty() const {
    return begin_ == end_;
  }

  Iter begin() const {
    return begin_;
  }

  Iter end() const {
    return end_;
  }

  Iter data() const {
    return begin_;
  }

  void clear() {
    begin_ = end_ = nullptr;
  }

  using reference = typename std::iterator_traits<Iter>::reference;

  reference operator[](size_t index) const {
    // Return the value at the specified index
    return *(begin_ + index);
  }
};

using StringPiece = Range<const char*>;
using ByteRange = Range<const uint8_t*>;
using MutableByteRange = Range<uint8_t*>;
} // namespace quic
