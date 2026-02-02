/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/common/QuicBuffer.h>

#include <algorithm>
#include <utility>

namespace quic {

QuicBuffer::QuicBuffer(std::size_t capacity)
    : sharedBuffer_(new (std::nothrow) uint8_t[capacity]),
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
    ByteRange range,
    std::size_t headroom,
    std::size_t minTailroom) {
  return copyBuffer(
      range.data(), (range.end() - range.begin()), headroom, minTailroom);
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
    const void* buf,
    std::size_t capacity) {
  return std::unique_ptr<QuicBuffer>(new (std::nothrow) QuicBuffer(
      capacity, (uint8_t*)buf, (uint8_t*)buf, capacity, nullptr));
}

std::unique_ptr<QuicBuffer> QuicBuffer::takeOwnership(
    void* buf,
    std::size_t capacity,
    FreeFunction freeFn,
    void* userData) {
  // If userData is provided without a freeFn, match IOBuf semantics by using
  // free(). However, in folly::IOBuf this is DCHECKed; we will DCHECK as well.
  MVDCHECK(!userData || (userData && freeFn));

  // Build a shared_ptr that owns the buffer and will free it appropriately.
  std::shared_ptr<uint8_t[]> shared{
      static_cast<uint8_t*>(buf), [freeFn, userData](uint8_t* p) {
        if (!p) {
          return;
        }
        if (freeFn) {
          freeFn(static_cast<void*>(p), userData);
        } else {
          // Default to free() if no custom free function is provided.
          free(static_cast<void*>(p));
        }
      }};

  return std::unique_ptr<QuicBuffer>(new (std::nothrow) QuicBuffer(
      capacity,
      static_cast<uint8_t*>(buf),
      static_cast<uint8_t*>(buf),
      capacity,
      std::move(shared)));
}

std::unique_ptr<QuicBuffer> QuicBuffer::wrapIov(
    const iovec* vec,
    size_t count) {
  QuicBuffer result;
  for (size_t i = 0; i < count; ++i) {
    size_t len = vec[i].iov_len;
    void* data = vec[i].iov_base;
    if (len > 0) {
      auto buf = wrapBuffer(data, len);
      result.appendToChain(std::move(buf));
    }
  }
  return result.isChained() ? result.pop() : create(0);
}

std::unique_ptr<QuicBuffer> QuicBuffer::fromString(
    std::unique_ptr<std::string> ptr) {
  // Take ownership of the string's underlying buffer and ensure the
  // std::string is deleted when the QuicBuffer is freed.
  auto ret = takeOwnership(
      static_cast<void*>(ptr->data()),
      ptr->size(),
      [](void*, void* userData) { delete static_cast<std::string*>(userData); },
      static_cast<void*>(ptr.get()));
  // Release ownership of the std::string from the unique_ptr, since the
  // QuicBuffer now owns its lifetime via the custom deleter.
  std::ignore = ptr.release();
  return ret;
}

std::unique_ptr<QuicBuffer> QuicBuffer::wrapBuffer(ByteRange range) {
  return wrapBuffer((void*)range.data(), range.size());
}

QuicBuffer QuicBuffer::wrapBufferAsValue(
    const void* buf,
    std::size_t capacity) noexcept {
  return {capacity, (uint8_t*)buf, (uint8_t*)buf, capacity, nullptr};
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

void QuicBuffer::appendChain(std::unique_ptr<QuicBuffer>&& quicBuffer) {
  // Just use appendToChain() on the next element in our chain
  next_->appendToChain(std::move(quicBuffer));
}

std::unique_ptr<QuicBuffer> QuicBuffer::separateChain(
    QuicBuffer* head,
    QuicBuffer* tail) {
  MVCHECK_NE(head, this);
  MVCHECK_NE(tail, this);

  head->prev_->next_ = tail->next_;
  tail->next_->prev_ = head->prev_;

  head->prev_ = tail;
  tail->next_ = head;

  return std::unique_ptr<QuicBuffer>(head);
}

void QuicBuffer::advance(std::size_t amount) noexcept {
  MVCHECK_LE(
      amount, tailroom(), "Not enough room to advance data in QuicBuffer");
  if (length_ > 0) {
    memmove(data_ + amount, data_, length_);
  }
  data_ += amount;
}

void QuicBuffer::retreat(std::size_t amount) noexcept {
  MVCHECK_LE(
      amount, headroom(), "Not enough room to retreat data in QuicBuffer");
  if (length_ > 0) {
    memmove(data_ - amount, data_, length_);
  }
  data_ -= amount;
}

void QuicBuffer::prepend(std::size_t amount) noexcept {
  MVCHECK_LE(
      amount, headroom(), "Not enough room to prepend data in QuicBuffer");
  data_ -= amount;
  length_ += amount;
}

bool QuicBuffer::isSharedOne() const noexcept {
  return !sharedBuffer_ || (sharedBuffer_.use_count() > 1);
}

bool QuicBuffer::isShared() const noexcept {
  const QuicBuffer* current = this;
  do {
    if (current->isSharedOne()) {
      return true;
    }
    current = current->next_;
  } while (current != this);
  return false;
}

std::unique_ptr<QuicBuffer> QuicBuffer::clone() const {
  auto tmp = cloneOneImpl();

  for (QuicBuffer* current = next_; current != this; current = current->next_) {
    tmp->appendToChain(current->cloneOneImpl());
  }

  return tmp;
}

std::unique_ptr<QuicBuffer> QuicBuffer::cloneCoalesced() const {
  // Calculate the total length of data across the entire chain
  const std::size_t totalLength = computeChainDataLength();

  // Get headroom from first buffer (this) and tailroom from last buffer
  const std::size_t newHeadroom = headroom();
  const std::size_t newTailroom = prev()->tailroom();

  // Create new buffer with capacity for headroom + data + tailroom
  const std::size_t newCapacity = newHeadroom + totalLength + newTailroom;
  auto newBuffer = create(newCapacity);
  if (!newBuffer) {
    return nullptr;
  }

  // Advance to leave headroom space
  newBuffer->advance(newHeadroom);

  // Copy data from all buffers in the chain
  const QuicBuffer* current = this;
  do {
    if (current->length() > 0) {
      std::memcpy(
          newBuffer->writableTail(), current->data(), current->length());
      newBuffer->append(current->length());
    }
    current = current->next();
  } while (current != this);

  return newBuffer;
}

ByteRange QuicBuffer::coalesce() {
  if (isChained()) {
    const std::size_t newHeadroom = headroom();
    const std::size_t newTailroom = prev()->tailroom();
    coalesceAndReallocate(newHeadroom, computeChainDataLength(), newTailroom);
  }
  return {data_, length_};
}

std::unique_ptr<QuicBuffer> QuicBuffer::pop() {
  QuicBuffer* next = next_;
  next_->prev_ = prev_;
  prev_->next_ = next_;
  prev_ = this;
  next_ = this;
  return std::unique_ptr<QuicBuffer>((next == this) ? nullptr : next);
}

QuicBuffer::FillIovResult QuicBuffer::fillIov(struct iovec* iov, size_t len)
    const {
  QuicBuffer const* p = this;
  size_t i = 0;
  size_t totalBytes = 0;
  while (i < len) {
    // some code can get confused by empty iovs, so skip them
    if (p->length() > 0) {
      iov[i].iov_base = const_cast<uint8_t*>(p->data());
      iov[i].iov_len = p->length();
      totalBytes += p->length();
      i++;
    }
    p = p->next();
    if (p == this) {
      return {.numIovecs = i, .totalLength = totalBytes};
    }
  }
  return {.numIovecs = 0, .totalLength = 0};
}

void QuicBuffer::clear() noexcept {
  data_ = buf_;
  length_ = 0;
}

std::unique_ptr<QuicBuffer> QuicBuffer::cloneOneImpl() const {
  return std::unique_ptr<QuicBuffer>(new (std::nothrow) QuicBuffer(
      capacity_, data_, buf_, length_, sharedBuffer_));
}

std::size_t QuicBuffer::computeChainDataLength() const noexcept {
  std::size_t fullLength = length_;
  for (QuicBuffer* current = next_; current != this; current = current->next_) {
    fullLength += current->length_;
  }
  return fullLength;
}

size_t QuicBuffer::countChainElements() const noexcept {
  size_t numElements = 1;
  for (QuicBuffer* current = next_; current != this; current = current->next_) {
    ++numElements;
  }
  return numElements;
}

bool QuicBuffer::empty() const noexcept {
  const QuicBuffer* current = this;
  do {
    if (current->length() != 0) {
      return false;
    }
    current = current->next_;
  } while (current != this);
  return true;
}

void QuicBuffer::trimStart(std::size_t amount) noexcept {
  MVDCHECK_LE(amount, length_);
  data_ += amount;
  length_ -= amount;
}

void QuicBuffer::trimEnd(std::size_t amount) noexcept {
  MVDCHECK_LE(amount, length_);
  length_ -= amount;
}

void QuicBuffer::coalesceAndReallocate(
    size_t newHeadroom,
    size_t newLength,
    size_t newTailroom) {
  QuicBuffer* end = this;
  std::size_t newCapacity = newLength + newHeadroom + newTailroom;

  // Allocate space for the coalesced buffer.
  std::shared_ptr<uint8_t[]> newSharedBuffer =
      std::shared_ptr<uint8_t[]>(new (std::nothrow) uint8_t[newCapacity]);

  // Copy the data into the new buffer
  uint8_t* newData = newSharedBuffer.get() + newHeadroom;
  uint8_t* p = newData;
  QuicBuffer* current = this;
  size_t remaining = newLength;
  do {
    if (current->length_ > 0) {
      MVCHECK_LE(current->length_, remaining);
      MVCHECK(current->data_ != nullptr);
      remaining -= current->length_;
      memcpy(p, current->data_, current->length_);
      p += current->length_;
    }
    current = current->next_;
  } while (current != end);
  MVCHECK_EQ(remaining, 0);

  capacity_ = newCapacity;
  buf_ = newSharedBuffer.get();
  data_ = newData;
  length_ = newLength;
  sharedBuffer_ = std::move(newSharedBuffer);

  // Separate from the rest of our chain.
  // Since we don't store the unique_ptr returned by separateChain(),
  // this will immediately delete the returned subchain.
  if (isChained()) {
    (void)separateChain(next_, current->prev_);
  }
}

std::unique_ptr<QuicBuffer> QuicBuffer::unlink() {
  next_->prev_ = prev_;
  prev_->next_ = next_;
  prev_ = this;
  next_ = this;
  return std::unique_ptr<QuicBuffer>(this);
}

bool QuicBufferEqualTo::operator()(const QuicBuffer* a, const QuicBuffer* b)
    const noexcept {
  // Handle null pointer cases
  if (a == nullptr && b == nullptr) {
    return true;
  }
  if (a == nullptr || b == nullptr) {
    return false;
  }

  // First check if both chains have the same total length
  std::size_t aLength = a->computeChainDataLength();
  std::size_t bLength = b->computeChainDataLength();

  if (aLength != bLength) {
    return false;
  }

  // If both are empty, they are equal
  if (aLength == 0) {
    return true;
  }

  // Compare data byte by byte across both chains
  const QuicBuffer* aCurrent = a;
  const QuicBuffer* bCurrent = b;
  std::size_t aOffset = 0;
  std::size_t bOffset = 0;

  // Skip empty buffers in both chains to start
  while (aCurrent->length() == 0) {
    aCurrent = aCurrent->next();
    if (aCurrent == a) {
      MVCHECK(false, "Unreachable, we checked aLength != 0");
    }
  }

  while (bCurrent->length() == 0) {
    bCurrent = bCurrent->next();
    if (bCurrent == b) {
      // All buffers in other chain are empty
      MVCHECK(false, "Unreachable, since aLength == bLength and aLength != 0");
    }
  }

  std::size_t remainingBytes = aLength;

  while (remainingBytes > 0) {
    // Get the number of bytes we can compare from current positions
    std::size_t aBytesAvailable = aCurrent->length() - aOffset;
    std::size_t bBytesAvailable = bCurrent->length() - bOffset;
    std::size_t bytesToCompare =
        std::min({aBytesAvailable, bBytesAvailable, remainingBytes});

    // Compare the bytes
    if (memcmp(
            aCurrent->data() + aOffset,
            bCurrent->data() + bOffset,
            bytesToCompare) != 0) {
      return false;
    }

    // Update offsets and remaining bytes
    aOffset += bytesToCompare;
    bOffset += bytesToCompare;
    remainingBytes -= bytesToCompare;

    // Move to next buffer if current buffer is exhausted
    if (aOffset == aCurrent->length()) {
      aCurrent = aCurrent->next();
      aOffset = 0;
      // Skip empty buffers
      while (aCurrent != a && aCurrent->length() == 0) {
        aCurrent = aCurrent->next();
      }
    }

    if (bOffset == bCurrent->length()) {
      bCurrent = bCurrent->next();
      bOffset = 0;
      // Skip empty buffers
      while (bCurrent != b && bCurrent->length() == 0) {
        bCurrent = bCurrent->next();
      }
    }
  }

  return true;
}

std::string QuicBuffer::toString() const {
  const std::size_t totalLength = computeChainDataLength();
  std::string out;
  out.resize(totalLength);

  std::size_t offset = 0;
  const QuicBuffer* current = this;
  do {
    if (current->length() > 0) {
      std::memcpy(out.data() + offset, current->data(), current->length());
      offset += current->length();
    }
    current = current->next();
  } while (current != this);

  return out;
}

} // namespace quic
