/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/BufAccessor.h>

namespace quic {

BufAccessor::BufAccessor(Buf buf)
    : buf_(std::move(buf)), capacity_(buf_->capacity()) {
  CHECK(!buf_->isShared() && !buf_->isChained());
}

BufAccessor::BufAccessor(size_t capacity)
    : BufAccessor(folly::IOBuf::createCombined(capacity)) {}

Buf BufAccessor::obtain() {
  Buf ret;
  buf_.swap(ret);
  return ret;
}

Buf& BufAccessor::buf() {
  return buf_;
}

void BufAccessor::release(Buf buf) {
  CHECK(!buf_) << "Can't override existing buf";
  CHECK(buf) << "Invalid Buf being released";
  CHECK_EQ(buf->capacity(), capacity_)
      << "Buf has wrong capacity, capacit_=" << capacity_
      << ", buf capacity=" << buf->capacity();
  CHECK(!buf->isChained()) << "Reject chained buf";
  buf_ = std::move(buf);
}

bool BufAccessor::ownsBuffer() const {
  return (buf_ != nullptr);
}

const uint8_t* BufAccessor::tail() const {
  return buf_->tail();
}

const uint8_t* BufAccessor::data() const {
  return buf_->data();
}

std::size_t BufAccessor::tailroom() const {
  return buf_->tailroom();
}

std::size_t BufAccessor::headroom() const {
  return buf_->headroom();
}

std::size_t BufAccessor::length() const {
  return buf_->length();
}

void BufAccessor::clear() {
  buf_->clear();
}

bool BufAccessor::isChained() const {
  return buf_->isChained();
}

void BufAccessor::trimEnd(std::size_t amount) {
  buf_->trimEnd(amount);
}

void BufAccessor::trimStart(std::size_t amount) {
  buf_->trimStart(amount);
}

uint8_t* BufAccessor::writableTail() {
  return buf_->writableTail();
}

void BufAccessor::append(std::size_t amount) {
  buf_->append(amount);
}

} // namespace quic
