/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <folly/Range.h>
#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>
#include <quic/common/ChainedByteRange.h>

namespace quic {

size_t fillIovec(Buf& buf, iovec (&vec)[16]);

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

  Buf clone() const {
    return chain_ ? chain_->clone() : nullptr;
  }

  const RawBuf* front() const {
    return chain_.get();
  }

  Buf splitAtMost(size_t n);

  size_t trimStartAtMost(size_t amount);

  void trimStart(size_t amount);

  void append(Buf&& buf);

 private:
  void appendToChain(Buf& dst, Buf&& src);
  Buf chain_;
  size_t chainLength_{0};
};

class BufAppender {
 public:
  BufAppender(RawBuf* data, size_t appendLen);

  template <class T>
  void writeBE(T data) {
    auto bigEndian = folly::Endian::big(data);
    push((uint8_t*)(&bigEndian), sizeof(bigEndian));
  }

  void push(const uint8_t* data, size_t len);

  void insert(Buf data);

 private:
  RawBuf* crtBuf_;
  RawBuf* head_;
  size_t appendLen_;
  bool lastBufShared_{false};
};

class BufWriter {
 public:
  explicit BufWriter(uint8_t* buffer, size_t most);

  template <class T>
  void writeBE(T data) {
    auto dataSize = sizeof(T);
    sizeCheck(dataSize);
    auto bigEndian = folly::Endian::big(data);
    push((uint8_t*)&bigEndian, dataSize);
  }

  void push(const uint8_t* data, size_t len);

  /**
   * Push len amount from data into the IOBuf, starting at IOBuf's destOffset
   * position. Given this is a back fill, we don't increase the written bytes
   * count for this API, since they should be already counted in a previous
   * append() call.
   */
  void backFill(const uint8_t* data, size_t len, size_t destOffset);

  // TODO: OK, "insert" is a lie. Inside, we copy. But I'd like the BufWriter
  // to have the same interface as BufAppender during the transition period.
  void insert(const RawBuf* data);
  void insert(const RawBuf* data, size_t limit);

  void insert(const ChainedByteRangeHead* data);
  void insert(const ChainedByteRangeHead* data, size_t limit);

  uint8_t* tail() {
    return writableTail_;
  }

  size_t getBytesWritten() {
    return written_;
  }

  void append(size_t len);

 private:
  // TODO: This is caller responsibility for now so the BufWriter conform with
  // BufAppender interface. But once BufAppender is replaced by BufWriter, we
  // should let BufWriter check the size and return error code if it fails to
  // write.
  void sizeCheck(size_t dataSize) {
    DCHECK(written_ + dataSize <= most_)
        << " written=" << written_ << " limit=" << most_;
  }

  void copy(const RawBuf* data, size_t limit);
  void copy(const ChainedByteRangeHead* data, size_t limit);

 private:
  uint8_t* buffer_;
  uint8_t* writableTail_;
  const size_t most_;
  size_t written_{0};
  size_t appendCount_{0};
};

} // namespace quic
