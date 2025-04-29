/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/mvfst-config.h>

#include <quic/api/QuicBatchWriter.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>

namespace quic {

class GSOPacketBatchWriter : public IOBufBatchWriter {
 public:
  explicit GSOPacketBatchWriter(size_t maxBufs);
  ~GSOPacketBatchWriter() override = default;

  void reset() override;
  bool needsFlush(size_t size) override;
  bool append(
      BufPtr&& buf,
      size_t size,
      const folly::SocketAddress& /*unused*/,
      QuicAsyncUDPSocket* /*unused*/) override;
  ssize_t write(QuicAsyncUDPSocket& sock, const folly::SocketAddress& address)
      override;

  void setTxTime(std::chrono::microseconds txTime) override {
    txTime_ = txTime;
  }

 private:
  // max number of buffer chains we can accumulate before we need to flush
  size_t maxBufs_{1};
  // current number of buffer chains  appended the buf_
  size_t currBufs_{0};
  // size of the previous buffer chain appended to the buf_
  size_t prevSize_{0};
  // tx time to use for the socket write
  std::chrono::microseconds txTime_{0us};
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
      BufPtr&& buf,
      size_t size,
      const folly::SocketAddress& addr,
      QuicAsyncUDPSocket* sock) override;
  ssize_t write(QuicAsyncUDPSocket& sock, const folly::SocketAddress& address)
      override;
  bool empty() const override;
  size_t size() const override;

  void setTxTime(std::chrono::microseconds txTime) override {
    txTime_ = txTime;
  }

 private:
  QuicConnectionStateBase& conn_;
  size_t maxPackets_;
  const uint8_t* lastPacketEnd_{nullptr};
  size_t prevSize_{0};
  size_t numPackets_{0};
  std::chrono::microseconds txTime_{0us};

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
      BufPtr&& buf,
      size_t size,
      const folly::SocketAddress& address,
      QuicAsyncUDPSocket* sock) override;
  ssize_t write(QuicAsyncUDPSocket& sock, const folly::SocketAddress& address)
      override;

 private:
  // max number of buffer chains we can accumulate before we need to flush
  size_t maxBufs_{1};
  // current number of buffer chains appended the buf_
  size_t currBufs_{0};
  // size of data in all the buffers
  size_t currSize_{0};
  // array of IOBufs
  std::vector<BufPtr> bufs_;
  std::vector<QuicAsyncUDPSocket::WriteOptions> options_;
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

  UnorderedMap<folly::SocketAddress, Index> addrMap_;
};

class SendmmsgGSOInplacePacketBatchWriter : public BatchWriter {
 public:
  explicit SendmmsgGSOInplacePacketBatchWriter(
      QuicConnectionStateBase& conn,
      size_t maxBufs);
  ~SendmmsgGSOInplacePacketBatchWriter() override = default;

  [[nodiscard]] bool empty() const override;

  [[nodiscard]] size_t size() const override;

  void reset() override;
  bool append(
      BufPtr&& buf,
      size_t size,
      const folly::SocketAddress& address,
      QuicAsyncUDPSocket* sock) override;
  ssize_t write(QuicAsyncUDPSocket& sock, const folly::SocketAddress& address)
      override;

 private:
  static const size_t kMaxIovecs = 64;

  QuicConnectionStateBase& conn_;

  // The point at which the last packet written by this BatchWriter ended.
  // The reason we need this is so that we can shift any data that was later
  // written to the buffer to the beginning of the buffer once we perform a
  // write.
  const uint8_t* lastPacketEnd_{nullptr};

  // max number of buffer chains we can accumulate before we need to flush
  size_t maxBufs_{1};
  // current number of buffer chains
  size_t currBufs_{0};
  // size of data in all the buffers
  size_t currSize_{0};

  // Given an index, buffers_[i] has all packets that need to be sent to
  // indexToAddr_[i] with the write options set to indexToOptions_[i].
  std::vector<std::vector<iovec>> buffers_;
  std::vector<folly::SocketAddress> indexToAddr_;
  std::vector<QuicAsyncUDPSocket::WriteOptions> indexToOptions_;

  // An address can correspond to many indices. For instance, consider the
  // case when we send 3 packets for a particular address. The first and second
  // have a size of 1000, whereas the third has a size of 1200.
  // The first two would have the same index, with GSO enabled, while the third
  // would have a different index, with GSO disabled.
  UnorderedMap<folly::SocketAddress, uint32_t> addrToMostRecentIndex_;
};

} // namespace quic
