/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Likely.h>
#include <cstring>

#include <quic/common/ContiguousCursor.h>

namespace quic {

ContiguousReadCursor::ContiguousReadCursor(
    const uint8_t* data,
    size_t size) noexcept
    : data_(data), end_(data + size) {}

bool ContiguousReadCursor::skip(size_t bytes) noexcept {
  if (FOLLY_UNLIKELY(!canAdvance(bytes))) {
    return false;
  }
  data_ += bytes;
  return true;
}

bool ContiguousReadCursor::tryReadFixedSizeString(
    std::string& str,
    size_t bytes) noexcept {
  if (FOLLY_UNLIKELY(!canAdvance(bytes))) {
    return false;
  }
  readFixedSizeString(str, bytes);
  return true;
}

bool ContiguousReadCursor::tryClone(
    std::unique_ptr<uint8_t[]>& buf,
    size_t bytes) noexcept {
  if (FOLLY_UNLIKELY(!canAdvance(bytes))) {
    return false;
  }
  clone(buf, bytes);
  return true;
}

bool ContiguousReadCursor::tryPull(void* buf, size_t bytes) noexcept {
  if (FOLLY_UNLIKELY(!canAdvance(bytes))) {
    return false;
  }
  pull(buf, bytes);
  return true;
}

void ContiguousReadCursor::readFixedSizeString(
    std::string& str,
    size_t bytes) noexcept {
  str.reserve(bytes);
  str.append(reinterpret_cast<const char*>(data_), bytes);
  data_ += bytes;
}

void ContiguousReadCursor::pull(void* buf, size_t bytes) noexcept {
  memcpy(buf, data_, bytes);
  data_ += bytes;
}

void ContiguousReadCursor::clone(
    std::unique_ptr<uint8_t[]>& buf,
    size_t bytes) noexcept {
  buf = std::make_unique<uint8_t[]>(bytes);
  memcpy(buf.get(), data_, bytes);
  data_ += bytes;
}

} // namespace quic
