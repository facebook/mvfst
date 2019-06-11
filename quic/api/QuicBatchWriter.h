/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <quic/QuicConstants.h>

namespace quic {
class BatchWriter {
 public:
  BatchWriter() = default;
  virtual ~BatchWriter() = default;

  // returns true if the batch does not contain any buffers
  virtual bool empty() const = 0;

  // returns the size in bytes of the batched buffers
  virtual size_t size() const = 0;

  // reset the internal state after a flush
  virtual void reset() = 0;

  // returns false if we need to flush before adding a new packet
  virtual bool needsFlush(size_t /*unused*/);

  /* append returns true if the
   * writer need to be flushed
   */
  virtual bool append(std::unique_ptr<folly::IOBuf>&& buf, size_t bufSize) = 0;
  virtual ssize_t write(
      folly::AsyncUDPSocket& sock,
      const folly::SocketAddress& address) = 0;
};

class IOBufBatchWriter : public BatchWriter {
 public:
  IOBufBatchWriter() = default;
  ~IOBufBatchWriter() override = default;

  bool empty() const override {
    return !buf_;
  }

  size_t size() const override {
    return buf_ ? buf_->computeChainDataLength() : 0;
  }

 protected:
  std::unique_ptr<folly::IOBuf> buf_;
};

class SinglePacketBatchWriter : public IOBufBatchWriter {
 public:
  SinglePacketBatchWriter() = default;
  ~SinglePacketBatchWriter() override = default;

  void reset() override;
  bool append(std::unique_ptr<folly::IOBuf>&& buf, size_t /*unused*/) override;
  ssize_t write(
      folly::AsyncUDPSocket& sock,
      const folly::SocketAddress& address) override;
};

class GSOPacketBatchWriter : public IOBufBatchWriter {
 public:
  explicit GSOPacketBatchWriter(size_t maxBufs);
  ~GSOPacketBatchWriter() override = default;

  void reset() override;
  bool needsFlush(size_t size) override;
  bool append(std::unique_ptr<folly::IOBuf>&& buf, size_t size) override;
  ssize_t write(
      folly::AsyncUDPSocket& sock,
      const folly::SocketAddress& address) override;

 private:
  // max number of buffer chains we can accumulate before we need to flush
  size_t maxBufs_{1};
  // current number of buffer chains  appended the buf_
  size_t currBufs_{0};
  // size of the previous buffer chain appended to the buf_
  size_t prevSize_{0};
};

class SendmmsgPacketBatchWriter : public BatchWriter {
 public:
  explicit SendmmsgPacketBatchWriter(size_t maxBufs);
  ~SendmmsgPacketBatchWriter() override = default;

  bool empty() const override;

  size_t size() const override;

  void reset() override;
  bool append(std::unique_ptr<folly::IOBuf>&& buf, size_t size) override;
  ssize_t write(
      folly::AsyncUDPSocket& sock,
      const folly::SocketAddress& address) override;

 private:
  // max number of buffer chains we can accumulate before we need to flush
  size_t maxBufs_{1};
  // size of data in all the buffers
  size_t currSize_{0};
  // array of IOBufs
  std::vector<std::unique_ptr<folly::IOBuf>> bufs_;
};

class BatchWriterFactory {
 public:
  static std::unique_ptr<BatchWriter> makeBatchWriter(
      folly::AsyncUDPSocket& sock,
      const quic::QuicBatchingMode& batchingMode,
      uint32_t batchSize);
};

} // namespace quic
