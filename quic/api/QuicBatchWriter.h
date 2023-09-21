/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Portability.h>
#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>
#include <quic/common/QuicAsyncUDPSocketWrapper.h>
#include <quic/common/QuicEventBase.h>
#include <quic/state/StateData.h>

namespace quic {
class BatchWriter {
 public:
  BatchWriter() = default;
  virtual ~BatchWriter() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }

  void setSock(QuicAsyncUDPSocketWrapper* sock);

  FOLLY_NODISCARD QuicEventBase* evb();

  int getAndResetFd();

  // returns true if the batch does not contain any buffers
  virtual bool empty() const = 0;

  // returns the size in bytes of the batched buffers
  virtual size_t size() const = 0;

  // reset the internal state after a flush
  virtual void reset() = 0;

  // returns true if we need to flush before adding a new packet
  virtual bool needsFlush(size_t /*unused*/);

  virtual void setTxTime(std::chrono::microseconds) {
    throw QuicInternalException(
        "setTxTime not supported", LocalErrorCode::INTERNAL_ERROR);
  }

  /* append returns true if the
   * writer needs to be flushed
   */
  virtual bool append(
      std::unique_ptr<folly::IOBuf>&& buf,
      size_t bufSize,
      const folly::SocketAddress& addr,
      QuicAsyncUDPSocketWrapper* sock) = 0;
  virtual ssize_t write(
      QuicAsyncUDPSocketWrapper& sock,
      const folly::SocketAddress& address) = 0;

 protected:
  QuicEventBase evb_;
  int fd_{-1};
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
  bool append(
      std::unique_ptr<folly::IOBuf>&& buf,
      size_t /*unused*/,
      const folly::SocketAddress& /*unused*/,
      QuicAsyncUDPSocketWrapper* /*unused*/) override;
  ssize_t write(
      QuicAsyncUDPSocketWrapper& sock,
      const folly::SocketAddress& address) override;
};

/**
 * This writer allows for single buf inplace writes.
 * The buffer is owned by the conn/accessor, and every append will trigger a
 * flush/write.
 */
class SinglePacketInplaceBatchWriter : public IOBufBatchWriter {
 public:
  explicit SinglePacketInplaceBatchWriter(QuicConnectionStateBase& conn)
      : conn_(conn) {}
  ~SinglePacketInplaceBatchWriter() override = default;

  void reset() override;
  bool append(
      std::unique_ptr<folly::IOBuf>&& /* buf */,
      size_t /*unused*/,
      const folly::SocketAddress& /*unused*/,
      QuicAsyncUDPSocketWrapper* /*unused*/) override;
  ssize_t write(
      QuicAsyncUDPSocketWrapper& sock,
      const folly::SocketAddress& address) override;
  [[nodiscard]] bool empty() const override;

 private:
  QuicConnectionStateBase& conn_;
};

class SendmmsgPacketBatchWriter : public BatchWriter {
 public:
  explicit SendmmsgPacketBatchWriter(size_t maxBufs);
  ~SendmmsgPacketBatchWriter() override = default;

  bool empty() const override;

  size_t size() const override;

  void reset() override;
  bool append(
      std::unique_ptr<folly::IOBuf>&& buf,
      size_t size,
      const folly::SocketAddress& /*unused*/,
      QuicAsyncUDPSocketWrapper* /*unused*/) override;
  ssize_t write(
      QuicAsyncUDPSocketWrapper& sock,
      const folly::SocketAddress& address) override;

 private:
  // max number of buffer chains we can accumulate before we need to flush
  size_t maxBufs_{1};
  // size of data in all the buffers
  size_t currSize_{0};
  // array of IOBufs
  std::vector<std::unique_ptr<folly::IOBuf>> bufs_;
};

struct BatchWriterDeleter {
  void operator()(BatchWriter* batchWriter);
};

using BatchWriterPtr = std::unique_ptr<BatchWriter, BatchWriterDeleter>;

bool useSinglePacketInplaceBatchWriter(
    uint32_t maxBatchSize,
    quic::DataPathType dataPathType);
} // namespace quic
