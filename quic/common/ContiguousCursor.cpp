/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Likely.h>
#include <folly/io/IOBuf.h>

#include <quic/common/ContiguousCursor.h>

namespace quic {

ContiguousReadCursor::ContiguousReadCursor(const folly::IOBuf& buf) noexcept
    : begin_(buf.data()), data_(buf.data()), end_(buf.tail()), buf_(buf) {
  CHECK(!buf.isChained());
}

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

bool ContiguousReadCursor::tryClone(Buf& buf, size_t bytes) noexcept {
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

void ContiguousReadCursor::clone(Buf& buf, size_t bytes) noexcept {
  buf = buf_.cloneOne();
  buf->clear();
  buf->advance(uintptr_t(data_ - begin_));
  buf->append(bytes);
  data_ += bytes;
}

} // namespace quic
