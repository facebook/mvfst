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
} // namespace quic
