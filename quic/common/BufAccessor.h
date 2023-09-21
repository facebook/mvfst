/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>

namespace quic {

class BufAccessor {
 public:
  virtual ~BufAccessor() = default;

  /**
   * BufAccessor gives caller the internal IOBuf.
   */
  virtual Buf obtain() = 0;

  /**
   * Caller releases the IOBuf back to the accessor to own. The capacity has to
   * match the original IOBuf.
   */
  virtual void release(Buf buf) = 0;

  /**
   * Returns whether the BufAccessor currently owns an IOBuf.
   */
  virtual bool ownsBuffer() const = 0;
};

class SimpleBufAccessor : public BufAccessor {
 public:
  // The result capacity could be higher than the desired capacity.
  explicit SimpleBufAccessor(size_t capacity);

  ~SimpleBufAccessor() override = default;

  Buf obtain() override;

  void release(Buf buf) override;

  bool ownsBuffer() const override;

 private:
  Buf buf_;
  size_t capacity_;
};

struct ScopedBufAccessor {
 public:
  explicit ScopedBufAccessor(BufAccessor* accessor) : bufAccessor_(accessor) {
    CHECK(bufAccessor_->ownsBuffer());
    buf_ = bufAccessor_->obtain();
  }

  ~ScopedBufAccessor() {
    bufAccessor_->release(std::move(buf_));
  }

  std::unique_ptr<folly::IOBuf>& buf() {
    return buf_;
  }

 private:
  BufAccessor* bufAccessor_;
  std::unique_ptr<folly::IOBuf> buf_;
};
} // namespace quic
