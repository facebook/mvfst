/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/lang/Bits.h>

namespace folly {
class IOBuf;
}

namespace quic {

class ContiguousReadCursor {
 public:
  explicit ContiguousReadCursor(const folly::IOBuf& buf) noexcept;

  const uint8_t* data() const {
    return data_;
  }

  const uint8_t* end() const {
    return end_;
  }

  size_t remaining() const {
    return uintptr_t(end_ - data_);
  }

  bool canAdvance(size_t bytes) const noexcept {
    return uintptr_t(end_ - data_) >= bytes;
  }

  bool isAtEnd() const noexcept {
    return data_ == end_;
  }

  using Buf = std::unique_ptr<folly::IOBuf>;
  bool skip(size_t bytes) noexcept;
  bool tryReadFixedSizeString(std::string& str, size_t bytes) noexcept;
  bool tryClone(Buf& buf, size_t bytes) noexcept;
  bool tryPull(void* buf, size_t bytes) noexcept;

  template <class T>
  bool tryReadBE(T& val) noexcept {
    if (FOLLY_UNLIKELY(!canAdvance(sizeof(T)))) {
      return false;
    }
    readBE(val);
    return true;
  }

  // lambda that returns bool if should rollback to where data_ was before
  // invoking function
  template <class T>
  void withRollback(T&& func) noexcept {
    const uint8_t* checkpoint = data_;
    if (func()) {
      data_ = checkpoint;
    }
  }

 private:
  void readFixedSizeString(std::string& str, size_t bytes) noexcept;
  void pull(void* buf, size_t bytes) noexcept;
  void clone(Buf& buf, size_t bytes) noexcept;

  template <class T>
  void readBE(T& val) noexcept {
    read(val);
    val = folly::Endian::big(val);
  }

  template <class T>
  void read(T& val) noexcept {
    val = folly::loadUnaligned<T>(data_);
    data_ += sizeof(T);
  }

  const uint8_t* const begin_{nullptr};
  const uint8_t* data_{nullptr};
  const uint8_t* const end_{nullptr};
  const folly::IOBuf& buf_;
};

} // namespace quic
