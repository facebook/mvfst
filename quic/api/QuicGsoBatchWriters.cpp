/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicGsoBatchWriters.h>

namespace {
// There is a known problem in the CloningScheduler that it may write a packet
// that's a few bytes larger than the original packet. If the original packet is
// a full packet, then the new packet will be larger than a full packet.
constexpr size_t kPacketSizeViolationTolerance = 10;
} // namespace

namespace quic {

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
    size_t size,
    const folly::SocketAddress& /*unused*/,
    QuicAsyncUDPSocketWrapper* /*unused*/) {
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
    QuicAsyncUDPSocketWrapper& sock,
    const folly::SocketAddress& address) {
  // Even though it's called writeGSO, it can handle individual writes by
  // setting gsoVal = 0.
  int gsoVal = currBufs_ > 1 ? static_cast<int>(prevSize_) : 0;
  auto options =
      folly::AsyncUDPSocket::WriteOptions(gsoVal, false /*zerocopyVal*/);
  options.txTime = txTime_;
  return sock.writeGSO(address, buf_, options);
}

GSOInplacePacketBatchWriter::GSOInplacePacketBatchWriter(
    QuicConnectionStateBase& conn,
    size_t maxPackets)
    : conn_(conn), maxPackets_(maxPackets) {}

void GSOInplacePacketBatchWriter::reset() {
  lastPacketEnd_ = nullptr;
  prevSize_ = 0;
  numPackets_ = 0;
  nextPacketSize_ = 0;
}

bool GSOInplacePacketBatchWriter::needsFlush(size_t size) {
  auto shouldFlush = prevSize_ && size > prevSize_;
  if (shouldFlush) {
    nextPacketSize_ = size;
  }
  return shouldFlush;
}

bool GSOInplacePacketBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& /*buf*/,
    size_t size,
    const folly::SocketAddress& /* addr */,
    QuicAsyncUDPSocketWrapper* /* sock */) {
  CHECK(!needsFlush(size));
  ScopedBufAccessor scopedBufAccessor(conn_.bufAccessor);
  auto& buf = scopedBufAccessor.buf();
  if (!lastPacketEnd_) {
    CHECK(prevSize_ == 0 && numPackets_ == 0);
    prevSize_ = size;
    lastPacketEnd_ = buf->tail();
    numPackets_ = 1;
    return false;
  }

  CHECK(prevSize_ && prevSize_ >= size);
  ++numPackets_;
  lastPacketEnd_ = buf->tail();
  if (prevSize_ > size || numPackets_ == maxPackets_) {
    return true;
  }
  return false;
}

/**
 * Write the buffer owned by conn_.bufAccessor to the sock, until
 * lastPacketEnd_. After write, everything in the buffer after lastPacketEnd_
 * will be moved to the beginning of the buffer, and buffer will be returned to
 * conn_.bufAccessor.
 */
ssize_t GSOInplacePacketBatchWriter::write(
    QuicAsyncUDPSocketWrapper& sock,
    const folly::SocketAddress& address) {
  ScopedBufAccessor scopedBufAccessor(conn_.bufAccessor);
  CHECK(lastPacketEnd_);
  auto& buf = scopedBufAccessor.buf();
  CHECK(!buf->isChained());
  CHECK(lastPacketEnd_ >= buf->data() && lastPacketEnd_ <= buf->tail())
      << "lastPacketEnd_=" << (long)lastPacketEnd_
      << " data=" << (long long)buf->data()
      << " tail=" << (long long)buf->tail();
  uint64_t diffToEnd = buf->tail() - lastPacketEnd_;
  CHECK(
      diffToEnd <= conn_.udpSendPacketLen ||
      (nextPacketSize_ && diffToEnd == nextPacketSize_))
      << "diffToEnd=" << diffToEnd << ", pktLimit=" << conn_.udpSendPacketLen
      << ", nextPacketSize_=" << nextPacketSize_;
  if (diffToEnd >= conn_.udpSendPacketLen + kPacketSizeViolationTolerance) {
    LOG(ERROR) << "Remaining buffer contents larger than udpSendPacketLen by "
               << (diffToEnd - conn_.udpSendPacketLen);
  }
  uint64_t diffToStart = lastPacketEnd_ - buf->data();
  buf->trimEnd(diffToEnd);
  // Even though it's called writeGSO, it can handle individual writes by
  // setting gsoVal = 0.
  int gsoVal = numPackets_ > 1 ? static_cast<int>(prevSize_) : 0;
  auto options =
      folly::AsyncUDPSocket::WriteOptions(gsoVal, false /*zerocopyVal*/);
  options.txTime = txTime_;
  auto bytesWritten = sock.writeGSO(address, buf, options);
  /**
   * If there is one more bytes after lastPacketEnd_, that means there is a
   * packet we choose not to write in this batch (e.g., it has a size larger
   * than all existing packets in this batch). So after the socket write, we
   * need to move that packet from the middle of the buffer to the beginning of
   * the buffer so make sure we maximize the buffer space. An alternative here
   * is to writem to write everything out in the previous sock write call. But
   * that needs a much bigger change in the IoBufQuicBatch API.
   */
  if (diffToEnd) {
    buf->trimStart(diffToStart);
    buf->append(diffToEnd);
    buf->retreat(diffToStart);
    auto bufLength = buf->length();
    CHECK_EQ(diffToEnd, bufLength)
        << "diffToEnd=" << diffToEnd << ", bufLength=" << bufLength;
    CHECK(
        bufLength <= conn_.udpSendPacketLen ||
        (nextPacketSize_ && bufLength == nextPacketSize_))
        << "bufLength=" << bufLength << ", pktLimit=" << conn_.udpSendPacketLen
        << ", nextPacketSize_=" << nextPacketSize_;
    CHECK(0 == buf->headroom()) << "headroom=" << buf->headroom();
  } else {
    buf->clear();
  }
  reset();
  return bytesWritten;
}

bool GSOInplacePacketBatchWriter::empty() const {
  return numPackets_ == 0;
}

size_t GSOInplacePacketBatchWriter::size() const {
  if (empty()) {
    return 0;
  }
  ScopedBufAccessor scopedBufAccessor(conn_.bufAccessor);
  CHECK(lastPacketEnd_);
  auto& buf = scopedBufAccessor.buf();
  CHECK(lastPacketEnd_ >= buf->data() && lastPacketEnd_ <= buf->tail());
  size_t ret = lastPacketEnd_ - buf->data();
  return ret;
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
  options_.clear();
  prevSize_.clear();
  addrs_.clear();
  addrMap_.clear();

  currBufs_ = 0;
  currSize_ = 0;
}

bool SendmmsgGSOPacketBatchWriter::append(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t size,
    const folly::SocketAddress& addr,
    QuicAsyncUDPSocketWrapper* sock) {
  setSock(sock);
  currSize_ += size;

  // insert the entry if not present
  auto& idx = addrMap_[addr];

  // try to see if we can append
  if (idx.valid()) {
    if (size <= prevSize_[idx]) {
      if ((options_[idx].gso == 0) ||
          (static_cast<size_t>(options_[idx].gso) == prevSize_[idx])) {
        // we can append
        options_[idx].gso = prevSize_[idx];
        prevSize_[idx] = size;
        bufs_[idx]->prependChain(std::move(buf));
        currBufs_++;

        // flush if we reach maxBufs_
        return (currBufs_ == maxBufs_);
      }
    }
  }

  // set the map index
  idx = bufs_.size();

  // add a new buffer
  bufs_.emplace_back(std::move(buf));

  // set the gso_ value to 0 for now
  // this will change if we append to this chain
  folly::AsyncUDPSocket::WriteOptions options(0, false);
  options_.emplace_back(options);
  prevSize_.emplace_back(size);
  addrs_.emplace_back(addr);

  currBufs_++;

  // flush if we reach maxBufs_
  return (currBufs_ == maxBufs_);
}

ssize_t SendmmsgGSOPacketBatchWriter::write(
    QuicAsyncUDPSocketWrapper& sock,
    const folly::SocketAddress& /*unused*/) {
  CHECK_GT(bufs_.size(), 0);
  if (bufs_.size() == 1) {
    return (currBufs_ > 1) ? sock.writeGSO(addrs_[0], bufs_[0], options_[0])
                           : sock.write(addrs_[0], bufs_[0]);
  }

  int ret = sock.writemGSO(
      folly::range(addrs_.data(), addrs_.data() + addrs_.size()),
      bufs_.data(),
      bufs_.size(),
      options_.data());

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

} // namespace quic
