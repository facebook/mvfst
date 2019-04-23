/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once
#include <quic/QuicException.h>
#include <quic/api/QuicBatchWriter.h>
#include <quic/state/StateData.h>

namespace quic {
class IOBufQuicBatch {
 public:
  IOBufQuicBatch(
      std::unique_ptr<BatchWriter>&& batchWriter,
      folly::AsyncUDPSocket& sock,
      folly::SocketAddress& peerAddress,
      QuicConnectionStateBase::HappyEyeballsState& happyEyeballsState);

  ~IOBufQuicBatch() = default;

  // returns true if it succeeds and false if the loop should end
  bool write(std::unique_ptr<folly::IOBuf>&& buf, size_t encodedSize);

  bool flush();

  FOLLY_ALWAYS_INLINE uint64_t getPktSent() const {
    return pktSent_;
  }

  void setContinueOnNetworkUnreachable(bool continueOnNetworkUnreachable);

 private:
  void reset();

  // flushes the internal buffers
  bool flushInternal();

  bool isNetworkUnreachable(int err);

  /**
   * Returns whether or not the errno can be retried later.
   */
  bool isRetriableError(int err);

  std::unique_ptr<BatchWriter> batchWriter_;
  folly::AsyncUDPSocket& sock_;
  folly::SocketAddress& peerAddress_;
  QuicConnectionStateBase::HappyEyeballsState& happyEyeballsState_;
  uint64_t pktSent_{0};
  bool continueOnNetworkUnreachable_{false};
};

} // namespace quic
