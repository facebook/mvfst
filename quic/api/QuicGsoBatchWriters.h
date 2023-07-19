/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#ifndef MVFST_USE_LIBEV

#include <quic/api/QuicBatchWriter.h>

namespace quic {

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
      QuicAsyncUDPSocketType* /*unused*/) override;
  ssize_t write(
      QuicAsyncUDPSocketType& sock,
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
      QuicAsyncUDPSocketType* sock) override;
  ssize_t write(
      QuicAsyncUDPSocketType& sock,
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
      QuicAsyncUDPSocketType* sock) override;
  ssize_t write(
      QuicAsyncUDPSocketType& sock,
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

} // namespace quic

#endif
