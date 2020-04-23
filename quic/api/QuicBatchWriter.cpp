/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/QuicBatchWriter.h>

namespace quic {
// BatchWriter
bool BatchWriter::needsFlush(size_t /*unused*/) {
  return false;
}

// SinglePacketBatchWriter
void SinglePacketBatchWriter::reset() {
  buf_.reset();
}

bool SinglePacketBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t /*unused*/) {
  buf_ = std::move(buf);

  // needs to be flushed
  return true;
}

ssize_t SinglePacketBatchWriter::write(
    folly::AsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  return sock.write(address, buf_);
}

// GSOPacketBatchWriter
GSOPacketBatchWriter::GSOPacketBatchWriter(size_t maxBufs)
    : maxBufs_(maxBufs) {}

void GSOPacketBatchWriter::reset() {
  buf_.reset(nullptr);
  currBufs_ = 0;
  prevSize_ = 0;
}

bool GSOPacketBatchWriter::needsFlush(size_t size) {
  // if we get a buffer with a size that is greater
  // than the prev one we need to flush
  return (prevSize_ && (size > prevSize_));
}

bool GSOPacketBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t size) {
  // first buffer
  if (!buf_) {
    DCHECK_EQ(currBufs_, 0);
    buf_ = std::move(buf);
    prevSize_ = size;
    currBufs_ = 1;

    return false; // continue
  }

  // now we've got an additional buffer
  // append it to the chain
  buf_->prependChain(std::move(buf));
  currBufs_++;

  // see if we've added a different size
  if (size != prevSize_) {
    CHECK_LT(size, prevSize_);
    return true;
  }

  // reached max buffers
  if (FOLLY_UNLIKELY(currBufs_ == maxBufs_)) {
    return true;
  }

  // does not need to be flushed yet
  return false;
}

ssize_t GSOPacketBatchWriter::write(
    folly::AsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  return (currBufs_ > 1)
      ? sock.writeGSO(address, buf_, static_cast<int>(prevSize_))
      : sock.write(address, buf_);
}

// SendmmsgPacketBatchWriter
SendmmsgPacketBatchWriter::SendmmsgPacketBatchWriter(size_t maxBufs)
    : maxBufs_(maxBufs) {
  bufs_.reserve(maxBufs);
}

bool SendmmsgPacketBatchWriter::empty() const {
  return !currSize_;
}

size_t SendmmsgPacketBatchWriter::size() const {
  return currSize_;
}

void SendmmsgPacketBatchWriter::reset() {
  bufs_.clear();
  currSize_ = 0;
}

bool SendmmsgPacketBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t size) {
  CHECK_LT(bufs_.size(), maxBufs_);
  bufs_.emplace_back(std::move(buf));
  currSize_ += size;

  // reached max buffers
  if (FOLLY_UNLIKELY(bufs_.size() == maxBufs_)) {
    return true;
  }

  // does not need to be flushed yet
  return false;
}

ssize_t SendmmsgPacketBatchWriter::write(
    folly::AsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  CHECK_GT(bufs_.size(), 0);
  if (bufs_.size() == 1) {
    return sock.write(address, bufs_[0]);
  }

  int ret = sock.writem(
      folly::range(&address, &address + 1), bufs_.data(), bufs_.size());

  if (ret <= 0) {
    return ret;
  }

  if (static_cast<size_t>(ret) == bufs_.size()) {
    return currSize_;
  }

  // this is a partial write - we just need to
  // return a different number than currSize_
  return 0;
}

// SendmmsgGSOPacketBatchWriter
SendmmsgGSOPacketBatchWriter::SendmmsgGSOPacketBatchWriter(size_t maxBufs)
    : maxBufs_(maxBufs) {
  bufs_.reserve(maxBufs);
}

bool SendmmsgGSOPacketBatchWriter::empty() const {
  return !currSize_;
}

size_t SendmmsgGSOPacketBatchWriter::size() const {
  return currSize_;
}

void SendmmsgGSOPacketBatchWriter::reset() {
  bufs_.clear();
  gso_.clear();
  currBufs_ = 0;
  currSize_ = 0;
  prevSize_ = 0;
}

bool SendmmsgGSOPacketBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t size) {
  currSize_ += size;
  // see if we need to start a new chain
  if (size > prevSize_) {
    bufs_.emplace_back(std::move(buf));
    // set the gso_ value to 0 for now
    // this will change if we append to this chain
    gso_.emplace_back(0);
    prevSize_ = size;
    currBufs_++;

    // reached max buffers
    if (FOLLY_UNLIKELY(currBufs_ == maxBufs_)) {
      return true;
    }

    return false;
  }

  gso_.back() = prevSize_;
  bufs_.back()->prependChain(std::move(buf));
  currBufs_++;

  // reached max buffers
  if (FOLLY_UNLIKELY(currBufs_ == maxBufs_)) {
    return true;
  }

  if (size < prevSize_) {
    // reset the prevSize_ so in the next loop
    // we will start a new chain
    prevSize_ = 0;
  }

  return false;
}

ssize_t SendmmsgGSOPacketBatchWriter::write(
    folly::AsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  CHECK_GT(bufs_.size(), 0);
  if (bufs_.size() == 1) {
    return (currBufs_ > 1) ? sock.writeGSO(address, bufs_[0], gso_[0])
                           : sock.write(address, bufs_[0]);
  }

  int ret = sock.writemGSO(
      folly::range(&address, &address + 1),
      bufs_.data(),
      bufs_.size(),
      gso_.data());

  if (ret <= 0) {
    return ret;
  }

  if (static_cast<size_t>(ret) == bufs_.size()) {
    return currSize_;
  }

  // this is a partial write - we just need to
  // return a different number than currSize_
  return 0;
}

// BatchWriterFactory
std::unique_ptr<BatchWriter> BatchWriterFactory::makeBatchWriter(
    folly::AsyncUDPSocket& sock,
    const quic::QuicBatchingMode& batchingMode,
    uint32_t batchSize) {
  switch (batchingMode) {
    case quic::QuicBatchingMode::BATCHING_MODE_NONE:
      return std::make_unique<SinglePacketBatchWriter>();
    case quic::QuicBatchingMode::BATCHING_MODE_GSO: {
      if (sock.getGSO() >= 0) {
        return std::make_unique<GSOPacketBatchWriter>(batchSize);
      }

      return std::make_unique<SinglePacketBatchWriter>();
    }
    case quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG:
      return std::make_unique<SendmmsgPacketBatchWriter>(batchSize);
    case quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO: {
      if (sock.getGSO() >= 0) {
        return std::make_unique<SendmmsgGSOPacketBatchWriter>(batchSize);
      }

      return std::make_unique<SendmmsgPacketBatchWriter>(batchSize);
    }
      // no default so we can catch missing case at compile time
  }

  folly::assume_unreachable();
}

} // namespace quic
