// Copyright 2004-present Facebook. All Rights Reserved.

#include "quic/common/BufUtil.h"

namespace quic {

Buf BufQueue::split(size_t n) {
  Buf result;
  while (n != 0) {
    if (chain_ == nullptr) {
      throw std::underflow_error(
          "Attempt to remove more bytes than are present in BufQueue");
    } else if (chain_->length() <= n) {
      n -= chain_->length();
      chainLength_ -= chain_->length();
      Buf remainder = chain_->pop();
      appendToChain(result, std::move(chain_));
      chain_ = std::move(remainder);
    } else {
      Buf clone = chain_->cloneOne();
      clone->trimEnd(clone->length() - n);
      appendToChain(result, std::move(clone));
      chain_->trimStart(n);
      chainLength_ -= n;
      break;
    }
  }
  if (UNLIKELY(result == nullptr)) {
    return folly::IOBuf::create(0);
  }
  return result;
}

size_t BufQueue::trimStartAtMost(size_t amount) {
  auto original = amount;
  while (amount > 0) {
    if (!chain_) {
      break;
    }
    if (chain_->length() > amount) {
      chain_->trimStart(amount);
      chainLength_ -= amount;
      amount = 0;
      break;
    }
    amount -= chain_->length();
    chainLength_ -= chain_->length();
    chain_ = chain_->pop();
  }
  return original - amount;
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

} // namespace quic
