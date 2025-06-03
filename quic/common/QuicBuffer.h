/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/SysUio.h>
#include <quic/common/QuicRange.h>
#include <cstring>
#include <memory>

namespace quic {

class QuicBuffer {
 public:
  enum CreateOp {
    CREATE = 0,
  };

  explicit QuicBuffer(std::size_t capacity);

  // Same as the previous constructor, just added the CreateOp
  // parameter so that just switching the typealiases works with
  // folly::IOBuf
  QuicBuffer(CreateOp createOp, std::size_t capacity);

  ~QuicBuffer();

  static std::unique_ptr<QuicBuffer> create(std::size_t capacity) {
    return std::unique_ptr<QuicBuffer>(new (std::nothrow) QuicBuffer(capacity));
  }

  // TODO: In folly, the createCombined call is optimized so that both the
  // IOBuf and the underlying buffer are allocated in a single call to malloc.
  // For now, we don't make this optimization, and instead just allocate it
  // the old-fashioned way.
  static std::unique_ptr<QuicBuffer> createCombined(std::size_t capacity) {
    return create(capacity);
  }

  static std::unique_ptr<QuicBuffer> copyBuffer(
      ByteRange span,
      std::size_t headroom = 0,
      std::size_t minTailroom = 0);

  static std::unique_ptr<QuicBuffer> copyBuffer(
      const std::string& input,
      std::size_t headroom = 0,
      std::size_t minTailroom = 0);

  static std::unique_ptr<QuicBuffer> copyBuffer(
      const void* data,
      std::size_t size,
      std::size_t headroom = 0,
      std::size_t minTailroom = 0);

  static std::unique_ptr<QuicBuffer> wrapBuffer(
      void* buf,
      std::size_t capacity);

  static std::unique_ptr<QuicBuffer> wrapBuffer(ByteRange range);

  static QuicBuffer wrapBufferAsValue(
      const void* buf,
      std::size_t capacity) noexcept;

  void advance(std::size_t amount) noexcept;

  void retreat(std::size_t amount) noexcept;

  bool isSharedOne() const noexcept;

  /*
   * Basic getters
   */
  uint8_t* writableTail() noexcept {
    return data_ + length_;
  }

  void append(std::size_t amount) noexcept {
    length_ += amount;
  }

  [[nodiscard]] std::size_t length() const noexcept {
    return length_;
  }

  QuicBuffer* next() noexcept {
    return next_;
  }

  [[nodiscard]] const QuicBuffer* next() const noexcept {
    return next_;
  }

  QuicBuffer* prev() noexcept {
    return prev_;
  }

  [[nodiscard]] const QuicBuffer* prev() const noexcept {
    return prev_;
  }

  [[nodiscard]] const uint8_t* data() const noexcept {
    return data_;
  }

  uint8_t* writableData() noexcept {
    return data_;
  }

  [[nodiscard]] const uint8_t* tail() const noexcept {
    return data_ + length_;
  }

  [[nodiscard]] std::size_t headroom() const noexcept {
    return std::size_t(data_ - buf_);
  }

  [[nodiscard]] std::size_t tailroom() const noexcept {
    return std::size_t((buf_ + capacity_) - tail());
  }

  [[nodiscard]] std::size_t capacity() const noexcept {
    return capacity_;
  }

  [[nodiscard]] std::size_t computeChainDataLength() const noexcept;

  bool isChained() const noexcept {
    return next_ != this;
  }

  size_t countChainElements() const noexcept;

  bool empty() const noexcept;

  /*
   * Operations to trim, append, split, clone, etc.
   */

  void trimStart(std::size_t amount) noexcept;

  void trimEnd(std::size_t amount) noexcept;

  void appendToChain(std::unique_ptr<QuicBuffer>&& quicBuffer);

  /*
   * If you have a chain (A, B, C, D, E, F), and you call A->separateChain(B,
   * D), then you will be returned the chain (B, C, D) and the current
   * QuicBuffer chain will change to (A, E, F).
   */
  std::unique_ptr<QuicBuffer> separateChain(QuicBuffer* head, QuicBuffer* tail);

  std::unique_ptr<QuicBuffer> clone() const;

  std::unique_ptr<QuicBuffer> cloneOne() const {
    return cloneOneImpl();
  }

  ByteRange coalesce();

  // Removes the rest of the chain from this IOBuf, and returns it. If there is
  // only one element in the chain, this is a no-op and returns nullptr.
  std::unique_ptr<QuicBuffer> pop();

  struct FillIovResult {
    // How many iovecs were filled (or 0 on error).
    size_t numIovecs;
    // The total length of filled iovecs (or 0 on error).
    size_t totalLength;
  };

  FillIovResult fillIov(struct iovec* iov, size_t len) const;

  class Iterator {
   public:
    explicit Iterator(const QuicBuffer* pos, const QuicBuffer* end)
        : pos_(pos), end_(end) {
      if (pos_) {
        setVal();
      }
    }

    Iterator() = default;

    Iterator(Iterator const& rhs) : Iterator(rhs.pos_, rhs.end_) {}

    Iterator& operator=(Iterator const& rhs) {
      pos_ = rhs.pos_;
      end_ = rhs.end_;
      if (pos_) {
        setVal();
      }
      return *this;
    }

    bool operator==(const Iterator& other) const {
      return equal(other);
    }

    bool operator!=(const Iterator& other) const {
      return !equal(other);
    }

    [[nodiscard]] const ByteRange* dereference() const {
      return &val_;
    }

    [[nodiscard]] bool equal(const Iterator& other) const {
      return pos_ == other.pos_ && end_ == other.end_;
    }

    void increment() {
      pos_ = pos_->next();
      adjustForEnd();
    }

    const ByteRange* operator->() const {
      return dereference();
    }

    ByteRange operator*() const {
      return val_;
    }

    Iterator& operator++() {
      increment();
      return *this;
    }

    Iterator operator++(int) {
      Iterator other = *this;
      increment();
      return other;
    }

   private:
    void setVal() {
      val_ = ByteRange(pos_->data(), pos_->tail());
    }

    void adjustForEnd() {
      if (pos_ == end_) {
        pos_ = end_ = nullptr;
        val_ = ByteRange();
      } else {
        setVal();
      }
    }

    const QuicBuffer* pos_{nullptr};
    const QuicBuffer* end_{nullptr};
    ByteRange val_;
  };

  [[nodiscard]] Iterator begin() const {
    return Iterator(this, this);
  }

  [[nodiscard]] Iterator end() const {
    return Iterator(nullptr, nullptr);
  }

 protected:
  QuicBuffer(
      std::size_t capacity,
      uint8_t* data,
      uint8_t* buf,
      std::size_t length,
      std::shared_ptr<uint8_t[]> sharedBuffer);

 private:
  void coalesceAndReallocate(
      size_t newHeadroom,
      size_t newLength,
      size_t newTailroom);

  std::unique_ptr<QuicBuffer> unlink();

  std::unique_ptr<QuicBuffer> cloneOneImpl() const;

  // This is set if the underlying buffer is shared.
  // Otherwise, if the buffer is owned externally, this is
  // set to nullptr.
  std::shared_ptr<uint8_t[]> sharedBuffer_;

  uint8_t* data_{nullptr};
  uint8_t* buf_{nullptr};
  QuicBuffer* next_{nullptr};
  QuicBuffer* prev_{nullptr};
  std::size_t length_{0};
  std::size_t capacity_{0};
};

} // namespace quic
