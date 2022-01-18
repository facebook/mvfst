/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Portability.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <quic/QuicConstants.h>
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

  void setSock(folly::AsyncUDPSocket* sock) {
    if (sock && !evb_) {
      fd_ = ::dup(sock->getNetworkSocket().toFd());
      evb_ = sock->getEventBase();
    }
  }

  FOLLY_NODISCARD folly::EventBase* evb() const {
    return evb_;
  }

  int getAndResetFd() {
    auto ret = fd_;
    fd_ = -1;

    return ret;
  }

  // returns true if the batch does not contain any buffers
  virtual bool empty() const = 0;

  // returns the size in bytes of the batched buffers
  virtual size_t size() const = 0;

  // reset the internal state after a flush
  virtual void reset() = 0;

  // returns true if we need to flush before adding a new packet
  virtual bool needsFlush(size_t /*unused*/);

  /* append returns true if the
   * writer needs to be flushed
   */
  virtual bool append(
      std::unique_ptr<folly::IOBuf>&& buf,
      size_t bufSize,
      const folly::SocketAddress& addr,
      folly::AsyncUDPSocket* sock) = 0;
  virtual ssize_t write(
      folly::AsyncUDPSocket& sock,
      const folly::SocketAddress& address) = 0;

 protected:
  folly::EventBase* evb_{nullptr};
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
      folly::AsyncUDPSocket* /*unused*/) override;
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
  bool append(
      std::unique_ptr<folly::IOBuf>&& buf,
      size_t size,
      const folly::SocketAddress& /*unused*/,
      folly::AsyncUDPSocket* /*unused*/) override;
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

class GSOInplacePacketBatchWriter : public BatchWriter {
 public:
  explicit GSOInplacePacketBatchWriter(
      QuicConnectionStateBase& conn,
      size_t maxPackets);
  ~GSOInplacePacketBatchWriter() override = default;

  void reset() override;
  bool needsFlush(size_t size) override;
  bool append(
      std::unique_ptr<folly::IOBuf>&& buf,
      size_t size,
      const folly::SocketAddress& addr,
      folly::AsyncUDPSocket* sock) override;
  ssize_t write(
      folly::AsyncUDPSocket& sock,
      const folly::SocketAddress& address) override;
  bool empty() const override;
  size_t size() const override;

 private:
  QuicConnectionStateBase& conn_;
  size_t maxPackets_;
  const uint8_t* lastPacketEnd_{nullptr};
  size_t prevSize_{0};
  size_t numPackets_{0};

  /**
   * If we flush the batch due to the next packet being larger than current GSO
   * size, we use the following value to keep track of that next packet, and
   * checks against buffer residue after writes. The reason we cannot just check
   * the buffer residue against the Quic packet limit is that there may be some
   * retranmission packets slightly larger than the limit.
   */
  size_t nextPacketSize_{0};
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
      folly::AsyncUDPSocket* /*unused*/) override;
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

class SendmmsgGSOPacketBatchWriter : public BatchWriter {
 public:
  explicit SendmmsgGSOPacketBatchWriter(size_t maxBufs);
  ~SendmmsgGSOPacketBatchWriter() override = default;

  bool empty() const override;

  size_t size() const override;

  void reset() override;
  bool append(
      std::unique_ptr<folly::IOBuf>&& buf,
      size_t size,
      const folly::SocketAddress& address,
      folly::AsyncUDPSocket* sock) override;
  ssize_t write(
      folly::AsyncUDPSocket& sock,
      const folly::SocketAddress& address) override;

 private:
  // max number of buffer chains we can accumulate before we need to flush
  size_t maxBufs_{1};
  // current number of buffer chains appended the buf_
  size_t currBufs_{0};
  // size of data in all the buffers
  size_t currSize_{0};
  // array of IOBufs
  std::vector<std::unique_ptr<folly::IOBuf>> bufs_;
  std::vector<int> gso_;
  std::vector<size_t> prevSize_;
  std::vector<folly::SocketAddress> addrs_;

  struct Index {
    Index& operator=(int idx) {
      idx_ = idx;
      return *this;
    }

    operator int() const {
      return idx_;
    }

    bool valid() const {
      return idx_ >= 0;
    }
    int idx_ = -1;
  };

  folly::F14FastMap<folly::SocketAddress, Index> addrMap_;
};

struct BatchWriterDeleter {
  void operator()(BatchWriter* batchWriter);
};

using BatchWriterPtr = std::unique_ptr<BatchWriter, BatchWriterDeleter>;

class BatchWriterFactory {
 public:
  static BatchWriterPtr makeBatchWriter(
      folly::AsyncUDPSocket& sock,
      const quic::QuicBatchingMode& batchingMode,
      uint32_t batchSize,
      bool useThreadLocal,
      const std::chrono::microseconds& threadLocalDelay,
      DataPathType dataPathType,
      QuicConnectionStateBase& conn);
};

} // namespace quic
