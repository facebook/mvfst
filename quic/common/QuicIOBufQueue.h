/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/QuicBuffer.h>
#include <cstddef>
#include <memory>
#include <stdexcept>

namespace quic {

/**
 * A minimal IOBufQueue abstraction with a subset of the API of
 * folly::IOBufQueue.
 */
class QuicIOBufQueue {
 public:
  struct Options {
    bool cacheChainLength;

    explicit Options(bool cache = false) : cacheChainLength(cache) {}
  };

  static Options cacheChainLength() {
    return Options(true);
  }

  QuicIOBufQueue() = default;

  explicit QuicIOBufQueue(const Options& /* options */) {}

  QuicIOBufQueue(QuicIOBufQueue&& other) noexcept
      : chain_(std::move(other.chain_)), chainLength_(other.chainLength_) {
    other.chainLength_ = 0;
  }

  QuicIOBufQueue& operator=(QuicIOBufQueue&& other) noexcept {
    if (&other != this) {
      chain_ = std::move(other.chain_);
      chainLength_ = other.chainLength_;
      other.chainLength_ = 0;
    }
    return *this;
  }

  QuicIOBufQueue(const QuicIOBufQueue&) = delete;
  QuicIOBufQueue& operator=(const QuicIOBufQueue&) = delete;

  [[nodiscard]] bool empty() const {
    return chainLength_ == 0;
  }

  [[nodiscard]] size_t chainLength() const {
    return chainLength_;
  }

  [[nodiscard]] const QuicBuffer* front() const {
    return chain_.get();
  }

  /**
   * Move the entire buffer chain out of this queue, leaving it empty.
   * Returns nullptr if the queue is empty.
   */
  std::unique_ptr<QuicBuffer> move() {
    chainLength_ = 0;
    return std::move(chain_);
  }

  /**
   * Split the first n bytes off the front of the queue.
   */
  std::unique_ptr<QuicBuffer> split(size_t n);

  /**
   * Split at most n bytes off the front.  If n >= chainLength(), moves and
   * returns the entire chain.
   */
  std::unique_ptr<QuicBuffer> splitAtMost(size_t n);

  /**
   * Trim at most amount bytes from the front.
   * Returns the number of bytes actually trimmed.
   */
  size_t trimStartAtMost(size_t amount);

  /**
   * Trim exactly amount bytes from the front.
   */
  void trimStart(size_t amount);

  /**
   * Append a buffer (or chain) to the back of the queue.
   * Empty buffers are silently ignored.
   */
  void append(std::unique_ptr<QuicBuffer>&& buf);

 private:
  static void appendToChain(
      std::unique_ptr<QuicBuffer>& dst,
      std::unique_ptr<QuicBuffer>&& src);

  std::unique_ptr<QuicBuffer> chain_;
  size_t chainLength_{0};
};

} // namespace quic
