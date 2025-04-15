/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
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
    Buf&& buf,
    size_t /*unused*/,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocket* /*unused*/) {
  buf_ = std::move(buf);

  // needs to be flushed
  return true;
}

ssize_t SinglePacketBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  iovec vec[kNumIovecBufferChains];
  size_t iovec_len = fillIovec(buf_, vec);
  return sock.write(address, vec, iovec_len);
}

// SinglePacketInplaceBatchWriter
void SinglePacketInplaceBatchWriter::reset() {
  conn_.bufAccessor->clear();
}

bool SinglePacketInplaceBatchWriter::append(
    Buf&& /* buf */,
    size_t /*unused*/,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocket* /*unused*/) {
  // Always flush. This should trigger a write afterwards.
  return true;
}

ssize_t SinglePacketInplaceBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  auto& buf = conn_.bufAccessor->buf();
  CHECK(!conn_.bufAccessor->isChained());

  iovec vec[kNumIovecBufferChains];
  size_t iovec_len = fillIovec(buf, vec);
  auto ret = sock.write(address, vec, iovec_len);
  conn_.bufAccessor->clear();
  return ret;
}

bool SinglePacketInplaceBatchWriter::empty() const {
  return conn_.bufAccessor->length() == 0;
}

// SinglePacketBackpressureBatchWriter
SinglePacketBackpressureBatchWriter::SinglePacketBackpressureBatchWriter(
    QuicConnectionStateBase& conn)
    : conn_(conn) {
  // If we have a write to retry from a previous attempt, pick that up.
  if (conn_.pendingWriteBatch_.buf) {
    buf_.swap(conn_.pendingWriteBatch_.buf);
    lastWriteSuccessful_ = false;
  }
}

SinglePacketBackpressureBatchWriter::~SinglePacketBackpressureBatchWriter() {
  if (buf_ && !buf_->empty()) {
    conn_.pendingWriteBatch_.buf.swap(buf_);
  }
}

void SinglePacketBackpressureBatchWriter::reset() {
  // Only clear the buffer if it's been written successfully.
  // Otherwise, retain it so it can be retried.
  if (lastWriteSuccessful_) {
    buf_.reset(nullptr);
  }
}

bool SinglePacketBackpressureBatchWriter::append(
    Buf&& buf,
    size_t /* unused */,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocket* /*unused*/) {
  buf_ = std::move(buf);

  // needs to be flushed
  return true;
}

ssize_t SinglePacketBackpressureBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  iovec vec[kNumIovecBufferChains];
  size_t iovec_len = fillIovec(buf_, vec);
  auto written = sock.write(address, vec, iovec_len);
  lastWriteSuccessful_ = written > 0;
  return written;
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
    Buf&& buf,
    size_t size,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocket* /*unused*/) {
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
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  CHECK_GT(bufs_.size(), 0);
  if (bufs_.size() == 1) {
    iovec vec[kNumIovecBufferChains];
    size_t iovec_len = fillIovec(bufs_.at(0), vec);
    return sock.write(address, vec, iovec_len);
  }

  size_t numChainedBuffers = 0;
  for (auto& buf : bufs_) {
    numChainedBuffers += buf->countChainElements();
  }

  int ret = 0;
  if (numChainedBuffers <= kNumIovecBufferChains &&
      bufs_.size() < kNumIovecBufferChains) {
    // We don't allocate arrays on the heap
    iovec vec[kNumIovecBufferChains];
    size_t messageSizes[kNumIovecBufferChains];
    fillIovecAndMessageSizes(vec, messageSizes, kNumIovecBufferChains);
    sock.writem(
        folly::range(&address, &address + 1), vec, messageSizes, bufs_.size());
  } else {
    // We allocate the arrays on the heap
    std::unique_ptr<iovec[]> vec(new iovec[numChainedBuffers]);
    std::unique_ptr<size_t[]> messageSizes(new size_t[bufs_.size()]);
    fillIovecAndMessageSizes(vec.get(), messageSizes.get(), numChainedBuffers);
    sock.writem(
        folly::range(&address, &address + 1),
        vec.get(),
        messageSizes.get(),
        bufs_.size());
  }

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

void SendmmsgPacketBatchWriter::fillIovecAndMessageSizes(
    iovec* vec,
    size_t* messageSizes,
    size_t iovecLen) {
  size_t currentIovecIndex = 0;
  for (uint32_t i = 0; i < bufs_.size(); i++) {
    size_t numIovecs =
        bufs_.at(i)
            ->fillIov(vec + currentIovecIndex, iovecLen - currentIovecIndex)
            .numIovecs;
    messageSizes[i] = numIovecs;
    currentIovecIndex += numIovecs;
  }
}

bool useSinglePacketInplaceBatchWriter(
    uint32_t maxBatchSize,
    quic::DataPathType dataPathType) {
  return maxBatchSize == 1 &&
      dataPathType == quic::DataPathType::ContinuousMemory;
}

SendmmsgInplacePacketBatchWriter::SendmmsgInplacePacketBatchWriter(
    QuicConnectionStateBase& conn,
    size_t maxBufs)
    : conn_(conn), maxBufs_(maxBufs) {
  CHECK_LT(maxBufs, kMaxIovecs) << "maxBufs must be less than " << kMaxIovecs;
}

bool SendmmsgInplacePacketBatchWriter::empty() const {
  return currSize_ == 0;
}

size_t SendmmsgInplacePacketBatchWriter::size() const {
  return currSize_;
}

void SendmmsgInplacePacketBatchWriter::reset() {
  currSize_ = 0;
  numPacketsBuffered_ = 0;
}

bool SendmmsgInplacePacketBatchWriter::append(
    Buf&& /* buf */,
    size_t size,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocket* /*unused*/) {
  CHECK_LT(numPacketsBuffered_, maxBufs_);

  auto& buf = conn_.bufAccessor->buf();
  CHECK(!buf->isChained() && buf->length() >= size);
  iovecs_[numPacketsBuffered_].iov_base = (void*)(buf->tail() - size);
  iovecs_[numPacketsBuffered_].iov_len = size;

  ++numPacketsBuffered_;
  currSize_ += size;

  // reached max buffers
  if (FOLLY_UNLIKELY(numPacketsBuffered_ == maxBufs_)) {
    return true;
  }

  // does not need to be flushed yet
  return false;
}

ssize_t SendmmsgInplacePacketBatchWriter::write(
    QuicAsyncUDPSocket& sock,
    const folly::SocketAddress& address) {
  CHECK_GT(numPacketsBuffered_, 0);

  auto& buf = conn_.bufAccessor->buf();
  buf->clear();

  if (numPacketsBuffered_ == 1) {
    return sock.write(address, &iovecs_[0], 1);
  }

  int ret = 0;
  std::array<size_t, kMaxIovecs> messageSizes{};

  for (size_t i = 0; i < numPacketsBuffered_; i++) {
    messageSizes[i] = 1;
  }

  sock.writem(
      folly::range(&address, &address + 1),
      &iovecs_[0],
      &messageSizes[0],
      numPacketsBuffered_);
  if (ret <= 0) {
    return ret;
  }

  if (static_cast<size_t>(ret) == numPacketsBuffered_) {
    return currSize_;
  }

  // this is a partial write - we just need to
  // return a different number than currSize_
  return 0;
}

} // namespace quic
