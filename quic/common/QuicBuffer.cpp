/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <glog/logging.h>
#include <quic/common/QuicBuffer.h>

#include <utility>

namespace quic {

QuicBuffer::QuicBuffer(std::size_t capacity)
    : sharedBuffer_(new(std::nothrow) uint8_t[capacity]),
      data_(sharedBuffer_.get()),
      buf_(data_),
      next_(this),
      prev_(this),
      capacity_(capacity) {}

QuicBuffer::QuicBuffer(CreateOp /* createOp */, std::size_t capacity)
    : QuicBuffer(capacity) {}

QuicBuffer::QuicBuffer(
    std::size_t capacity,
    uint8_t* data,
    uint8_t* buf,
    std::size_t length,
    std::shared_ptr<uint8_t[]> sharedBuffer)
    : sharedBuffer_(std::move(sharedBuffer)),
      data_(data),
      buf_(buf),
      next_(this),
      prev_(this),
      length_(length),
      capacity_(capacity) {}

QuicBuffer::~QuicBuffer() {
  // Destroying a QuicBuffer destroys the entire chain.
  while (next_ != this) {
    // Since unlink() returns unique_ptr() and we don't store it,
    // it will automatically delete the unlinked element.
    next_->unlink();
  }
}

std::unique_ptr<QuicBuffer> QuicBuffer::unlink() {
  next_->prev_ = prev_;
  prev_->next_ = next_;
  prev_ = this;
  next_ = this;
  return std::unique_ptr<QuicBuffer>(this);
}

} // namespace quic
