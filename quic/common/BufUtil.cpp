/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/BufUtil.h>

namespace quic {

Buf BufQueue::splitAtMost(size_t len) {
  folly::IOBuf* current = chain_.get();
  // empty queue / requested 0 bytes
  if (current == nullptr || len == 0) {
    return folly::IOBuf::create(0);
  }
  // entire chain requested
  if (len >= chainLength_) {
    return move();
  }

  chainLength_ -= len;
  Buf result;
  /**
   * Find the last IOBuf containing range requested. This will definitively
   * terminate without looping back to chain_ since we know chainLength_ > len.
   */
  while (len != 0) {
    if (current->length() > len) {
      break;
    }
    len -= current->length();
    current = current->next();
  }

  if (len == 0) {
    // edge case if last chunk ended exactly "len" bytes; we know this can't be
    // the last IOBuf in the list since otherwise len >= chainLength_
    result = current->separateChain(chain_.get(), current->prev());
  } else {
    // clone current node and remove overlap b/n result & chain_
    result = current->cloneOne();
    result->trimEnd(current->length() - len);
    current->trimStart(len);

    // if current isn't head node, move all prior nodes into result
    if (current != chain_.get()) {
      result->appendToChain(
          current->separateChain(chain_.get(), current->prev()));
      result = Buf(result.release()->next());
    }
  }
  // update chain_
  (void)chain_.release();
  chain_ = std::unique_ptr<folly::IOBuf>(current);
  DCHECK_EQ(chainLength_, chain_ ? chain_->computeChainDataLength() : 0);
  return result;
}

size_t BufQueue::trimStartAtMost(size_t amount) {
  folly::IOBuf* current = chain_.get();
  // empty queue / requested 0 bytes
  if (current == nullptr || amount == 0) {
    return 0;
  }
  // requested *strictly more* than entire chain, free chain_
  if (amount > chainLength_) {
    size_t result = chainLength_;
    move();
    return result;
  }

  const size_t originalAmount = amount;
  // find last IOBuf within the range requested
  while (amount > 0) {
    if (current->length() >= amount) {
      break;
    }
    amount -= current->length();
    current = current->next();
  }
  // only trim last buf in range, the prior bufs will be deleted
  current->trimStart(amount);

  // if current isn't head node, destruct all prior nodes
  if (current != chain_.get()) {
    current->separateChain(chain_.get(), current->prev());
  }

  // update chain_ to current
  (void)chain_.release();
  chain_.reset(current);
  // adjust chainLength_
  chainLength_ -= originalAmount;

  return originalAmount;
}

// TODO replace users with trimStartAtMost
void BufQueue::trimStart(size_t amount) {
  auto trimmed = trimStartAtMost(amount);
  if (trimmed != amount) {
    throw std::underflow_error(
        "Attempt to trim more bytes than are present in BufQueue");
  }
}

void BufQueue::append(Buf&& buf) {
  if (!buf || buf->empty()) {
    return;
  }
  chainLength_ += buf->computeChainDataLength();
  appendToChain(chain_, std::move(buf));
}

void BufQueue::appendToChain(Buf& dst, Buf&& src) {
  if (dst == nullptr) {
    dst = std::move(src);
  } else {
    dst->prependChain(std::move(src));
  }
}

BufAppender::BufAppender(folly::IOBuf* data, size_t appendLen)
    : crtBuf_(CHECK_NOTNULL(data)), head_(data), appendLen_(appendLen) {}

void BufAppender::push(const uint8_t* data, size_t len) {
  if (crtBuf_->tailroom() < len || lastBufShared_) {
    auto newBuf = folly::IOBuf::createCombined(std::max(appendLen_, len));
    folly::IOBuf* newBufPtr = newBuf.get();
    head_->prependChain(std::move(newBuf));
    crtBuf_ = newBufPtr;
  }
  memcpy(crtBuf_->writableTail(), data, len);
  crtBuf_->append(len);
  lastBufShared_ = false;
}

void BufAppender::insert(std::unique_ptr<folly::IOBuf> data) {
  // just skip the current buffer and append it to the end of the current
  // buffer.
  folly::IOBuf* dataPtr = data.get();
  // If the buffer is shared we do not want to overrwrite the tail of the
  // buffer.
  lastBufShared_ = data->isShared();
  head_->prependChain(std::move(data));
  crtBuf_ = dataPtr;
}

BufWriter::BufWriter(folly::IOBuf& iobuf, size_t most)
    : iobuf_(iobuf), most_(most) {
  CHECK(iobuf_.tailroom() >= most_)
      << "Buffer room=" << iobuf_.tailroom() << " limit=" << most_;
}

void BufWriter::push(const uint8_t* data, size_t len) {
  sizeCheck(len);
  memcpy(iobuf_.writableTail(), data, len);
  iobuf_.append(len);
  written_ += len;
}

void BufWriter::insert(const folly::IOBuf* data) {
  auto totalLength = data->computeChainDataLength();
  insert(data, totalLength);
}

void BufWriter::insert(const folly::IOBuf* data, size_t limit) {
  copy(data, limit);
}

void BufWriter::append(size_t len) {
  iobuf_.append(len);
  written_ += len;
  appendCount_ += len;
}

void BufWriter::copy(const folly::IOBuf* data, size_t limit) {
  if (!limit) {
    return;
  }
  sizeCheck(limit);
  size_t totalInserted = 0;
  const folly::IOBuf* curBuf = data;
  auto remaining = limit;
  do {
    auto lenToCopy = std::min(curBuf->length(), remaining);
    push(curBuf->data(), lenToCopy);
    totalInserted += lenToCopy;
    remaining -= lenToCopy;
    if (lenToCopy < curBuf->length()) {
      break;
    }
    curBuf = curBuf->next();
  } while (remaining && curBuf != data);
  CHECK_GE(limit, totalInserted);
}

void BufWriter::backFill(const uint8_t* data, size_t len, size_t destOffset) {
  CHECK_GE(appendCount_, len);
  appendCount_ -= len;
  CHECK_LE(destOffset + len, iobuf_.length());
  memcpy(iobuf_.writableData() + destOffset, data, len);
}
} // namespace quic
