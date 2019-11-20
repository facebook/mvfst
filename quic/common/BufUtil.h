// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once
#include <folly/io/IOBuf.h>

namespace quic {
using Buf = std::unique_ptr<folly::IOBuf>;

class BufQueue {
 public:
  BufQueue() = default;

  BufQueue(Buf chain) : chain_(std::move(chain)) {
    if (chain_) {
      chainLength_ = chain_->computeChainDataLength();
    }
  }

  BufQueue(BufQueue&& other) noexcept
      : chain_(std::move(other.chain_)), chainLength_(other.chainLength_) {
    other.chainLength_ = 0;
  }

  BufQueue& operator=(BufQueue&& other) {
    if (&other != this) {
      chain_ = std::move(other.chain_);
      chainLength_ = other.chainLength_;
      other.chainLength_ = 0;
    }
    return *this;
  }

  BufQueue(const BufQueue&) = delete;
  BufQueue& operator=(const BufQueue&) = delete;

  size_t chainLength() const {
    return chainLength_;
  }

  bool empty() const {
    return chainLength_ == 0;
  }

  Buf move() {
    chainLength_ = 0;
    return std::move(chain_);
  }

  const folly::IOBuf* front() const {
    return chain_.get();
  }

  Buf split(size_t n);

  size_t trimStartAtMost(size_t amount);

  void trimStart(size_t amount);

  void append(Buf&& buf);

 private:
  void appendToChain(Buf& dst, Buf&& src);
  Buf chain_;
  size_t chainLength_{0};
};

} // namespace quic
