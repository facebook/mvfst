/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/QuicIOBufQueue.h>

namespace quic {

std::unique_ptr<QuicBuffer> QuicIOBufQueue::split(size_t n) {
  if (n == 0) {
    return QuicBuffer::create(0);
  }
  return splitAtMost(n);
}

std::unique_ptr<QuicBuffer> QuicIOBufQueue::splitAtMost(size_t len) {
  QuicBuffer* current = chain_.get();
  // empty queue / requested 0 bytes
  if (current == nullptr || len == 0) {
    return QuicBuffer::create(0);
  }
  // entire chain requested
  if (len >= chainLength_) {
    return move();
  }

  chainLength_ -= len;
  std::unique_ptr<QuicBuffer> result;
  /**
   * Find the last QuicBuffer containing range requested. This will
   * definitively terminate without looping back to chain_ since we know
   * chainLength_ > len.
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
    // the last QuicBuffer in the list since otherwise len >= chainLength_
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
      result = std::unique_ptr<QuicBuffer>(result.release()->next());
    }
  }
  // update chain_
  (void)chain_.release();
  chain_ = std::unique_ptr<QuicBuffer>(current);
  return result;
}

size_t QuicIOBufQueue::trimStartAtMost(size_t amount) {
  QuicBuffer* current = chain_.get();
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
  // find last QuicBuffer within the range requested
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

void QuicIOBufQueue::trimStart(size_t amount) {
  trimStartAtMost(amount);
}

void QuicIOBufQueue::append(std::unique_ptr<QuicBuffer>&& buf) {
  if (!buf || buf->empty()) {
    return;
  }
  chainLength_ += buf->computeChainDataLength();
  appendToChain(chain_, std::move(buf));
}

void QuicIOBufQueue::appendToChain(
    std::unique_ptr<QuicBuffer>& dst,
    std::unique_ptr<QuicBuffer>&& src) {
  if (dst == nullptr) {
    dst = std::move(src);
  } else {
    dst->appendToChain(std::move(src));
  }
}

} // namespace quic
