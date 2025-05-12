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

std::unique_ptr<QuicBuffer> QuicBuffer::copyBuffer(
    std::span<const uint8_t> span,
    std::size_t headroom,
    std::size_t minTailroom) {
  return copyBuffer(
      span.data(), (span.end() - span.begin()), headroom, minTailroom);
}

std::unique_ptr<QuicBuffer> QuicBuffer::copyBuffer(
    const std::string& input,
    std::size_t headroom,
    std::size_t minTailroom) {
  return copyBuffer(input.data(), input.size(), headroom, minTailroom);
}

std::unique_ptr<QuicBuffer> QuicBuffer::copyBuffer(
    const void* data,
    std::size_t size,
    std::size_t headroom,
    std::size_t minTailroom) {
  std::size_t capacity = size + headroom + minTailroom;
  std::unique_ptr<QuicBuffer> quicBuffer = create(capacity);
  quicBuffer->advance(headroom);
  if (size != 0) {
    memcpy(quicBuffer->writableData(), data, size);
  }
  quicBuffer->append(size);
  return quicBuffer;
}

std::unique_ptr<QuicBuffer> QuicBuffer::wrapBuffer(
    void* buf,
    std::size_t capacity) {
  return std::unique_ptr<QuicBuffer>(new (std::nothrow) QuicBuffer(
      capacity, (uint8_t*)buf, (uint8_t*)buf, capacity, nullptr));
}

std::unique_ptr<QuicBuffer> QuicBuffer::wrapBuffer(
    std::span<const uint8_t> span) {
  return wrapBuffer((void*)span.data(), span.size());
}

void QuicBuffer::appendToChain(std::unique_ptr<QuicBuffer>&& quicBuffer) {
  // Take ownership of the specified IOBuf
  QuicBuffer* other = quicBuffer.release();

  // Remember the pointer to the tail of the other chain
  QuicBuffer* otherTail = other->prev_;

  // Hook up prev_->next_ to point at the start of the other chain,
  // and other->prev_ to point at prev_
  prev_->next_ = other;
  other->prev_ = prev_;

  // Hook up otherTail->next_ to point at us,
  // and prev_ to point back at otherTail,
  otherTail->next_ = this;
  prev_ = otherTail;
}

std::unique_ptr<QuicBuffer> QuicBuffer::separateChain(
    QuicBuffer* head,
    QuicBuffer* tail) {
  CHECK_NE(head, this);
  CHECK_NE(tail, this);

  head->prev_->next_ = tail->next_;
  tail->next_->prev_ = head->prev_;

  head->prev_ = tail;
  tail->next_ = head;

  return std::unique_ptr<QuicBuffer>(head);
}

void QuicBuffer::advance(std::size_t amount) noexcept {
  CHECK_LE(amount, tailroom())
      << "Not enough room to advance data in QuicBuffer";
  if (length_ > 0) {
    memmove(data_ + amount, data_, length_);
  }
  data_ += amount;
}

std::unique_ptr<QuicBuffer> QuicBuffer::clone() const {
  auto tmp = cloneOneImpl();

  for (QuicBuffer* current = next_; current != this; current = current->next_) {
    tmp->appendToChain(current->cloneOneImpl());
  }

  return tmp;
}

std::unique_ptr<QuicBuffer> QuicBuffer::cloneOneImpl() const {
  return std::unique_ptr<QuicBuffer>(new (std::nothrow) QuicBuffer(
      capacity_, data_, buf_, length_, sharedBuffer_));
}

std::unique_ptr<QuicBuffer> QuicBuffer::unlink() {
  next_->prev_ = prev_;
  prev_->next_ = next_;
  prev_ = this;
  next_ = this;
  return std::unique_ptr<QuicBuffer>(this);
}

} // namespace quic
