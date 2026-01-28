/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/SysUio.h>
#include <quic/common/QuicRange.h>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string>

namespace quic {

class QuicBuffer {
 public:
  using FreeFunction = void (*)(void* buf, void* userData);

  enum CreateOp {
    CREATE = 0,
  };

  QuicBuffer() : next_(this), prev_(this) {}

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
      const void* buf,
      std::size_t capacity);

  // Create a QuicBuffer from a std::string without copying the contents.
  // The returned QuicBuffer will take ownership of the string's storage
  // and delete the std::string when the buffer is freed, mirroring
  // folly::IOBuf::fromString semantics.
  static std::unique_ptr<QuicBuffer> fromString(std::unique_ptr<std::string>);

  static std::unique_ptr<QuicBuffer> fromString(std::string s) {
    return fromString(std::make_unique<std::string>(std::move(s)));
  }

  static std::unique_ptr<QuicBuffer> wrapBuffer(ByteRange range);

  // Take ownership of an external buffer and free it using freeFn(userData)
  // semantics matching folly::IOBuf::takeOwnership.
  static std::unique_ptr<QuicBuffer> takeOwnership(
      void* buf,
      std::size_t capacity,
      FreeFunction freeFn = nullptr,
      void* userData = nullptr);

  // Convert an iovec array into a QuicBuffer chain.
  // Wraps a number of iovecs into a QuicBuffer chain. If count == 0 or all
  // iovecs have zero length, returns a zero-length buffer. This function never
  // returns nullptr.
  static std::unique_ptr<QuicBuffer> wrapIov(const iovec* vec, size_t count);

  static QuicBuffer wrapBufferAsValue(
      const void* buf,
      std::size_t capacity) noexcept;

  void advance(std::size_t amount) noexcept;

  void retreat(std::size_t amount) noexcept;

  [[nodiscard]] bool isSharedOne() const noexcept;

  [[nodiscard]] bool isShared() const noexcept;

  /*
   * Basic getters
   */
  uint8_t* writableTail() noexcept {
    return data_ + length_;
  }

  void append(std::size_t amount) noexcept {
    length_ += amount;
  }

  void prepend(std::size_t amount) noexcept;

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

  [[nodiscard]] bool isChained() const noexcept {
    return next_ != this;
  }

  [[nodiscard]] size_t countChainElements() const noexcept;

  [[nodiscard]] bool empty() const noexcept;

  /*
   * Operations to trim, append, split, clone, etc.
   */

  void trimStart(std::size_t amount) noexcept;

  void trimEnd(std::size_t amount) noexcept;

  void appendToChain(std::unique_ptr<QuicBuffer>&& quicBuffer);

  void appendChain(std::unique_ptr<QuicBuffer>&& quicBuffer);

  /*
   * If you have a chain (A, B, C, D, E, F), and you call A->separateChain(B,
   * D), then you will be returned the chain (B, C, D) and the current
   * QuicBuffer chain will change to (A, E, F).
   */
  std::unique_ptr<QuicBuffer> separateChain(QuicBuffer* head, QuicBuffer* tail);

  [[nodiscard]] std::unique_ptr<QuicBuffer> clone() const;

  [[nodiscard]] std::unique_ptr<QuicBuffer> cloneOne() const {
    return cloneOneImpl();
  }

  /**
   * Copy a QuicBuffer chain into a single buffer.
   *
   * Semantically similar to .clone().coalesce(), but without the intermediate
   * allocations.
   *
   * The new QuicBuffer will have at least as much headroom as the first
   * QuicBuffer in the chain, and at least as much tailroom as the last
   * QuicBuffer in the chain.
   *
   * @return  A QuicBuffer for which isChained() == false, and whose data is the
   *          same as coalesce(). Returns nullptr if we fail to allocate memory.
   */
  [[nodiscard]] std::unique_ptr<QuicBuffer> cloneCoalesced() const;

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

  /**
   * Non-destructively convert this QuicBuffer chain into a std::string.
   */
  [[nodiscard]] std::string toString() const;

  void clear() noexcept;

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

    const ByteRange& operator*() const {
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

  [[nodiscard]] std::unique_ptr<QuicBuffer> cloneOneImpl() const;

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

// Functor class to compare two QuicBuffer chains for equality
// Two QuicBuffers are equal if their contents, when considered as a single
// contiguous buffer, are identical
class QuicBufferEqualTo {
 public:
  [[nodiscard]] bool operator()(const QuicBuffer* a, const QuicBuffer* b)
      const noexcept;

  [[nodiscard]] bool operator()(
      const std::unique_ptr<QuicBuffer>& a,
      const std::unique_ptr<QuicBuffer>& b) const noexcept {
    return operator()(a.get(), b.get());
  }

  [[nodiscard]] bool operator()(const QuicBuffer& a, const QuicBuffer& b)
      const noexcept {
    return operator()(&a, &b);
  }
};

} // namespace quic
