/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/BufAccessor.h>

namespace quic {
SimpleBufAccessor::SimpleBufAccessor(size_t capacity)
    : buf_(folly::IOBuf::createCombined(capacity)),
      capacity_(buf_->capacity()) {}

Buf SimpleBufAccessor::obtain() {
  Buf ret;
  buf_.swap(ret);
  return ret;
}

void SimpleBufAccessor::release(Buf buf) {
  CHECK(!buf_) << "Can't override existing buf";
  CHECK(buf) << "Invalid Buf being released";
  CHECK_EQ(buf->capacity(), capacity_)
      << "Buf has wrong capacity, capacit_=" << capacity_
      << ", buf capacity=" << buf->capacity();
  CHECK(!buf->isChained()) << "Reject chained buf";
  buf_ = std::move(buf);
}

bool SimpleBufAccessor::ownsBuffer() const {
  return (buf_ != nullptr);
}
} // namespace quic
