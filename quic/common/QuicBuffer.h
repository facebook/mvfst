/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <cstring>
#include <memory>
#include <span>

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
      std::span<const uint8_t> span,
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

  void advance(std::size_t amount) noexcept;

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

  /*
   * Operations to append, split, clone, etc.
   */

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

 protected:
  QuicBuffer(
      std::size_t capacity,
      uint8_t* data,
      uint8_t* buf,
      std::size_t length,
      std::shared_ptr<uint8_t[]> sharedBuffer);

 private:
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
  const std::size_t capacity_{0};
};

} // namespace quic
