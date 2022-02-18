/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <quic/QuicException.h>
#include <quic/api/QuicBatchWriter.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

struct BufQuicBatchResult {
  uint64_t packetsSent{0};
  uint64_t bytesSent{0};
};

class IOBufQuicBatch {
 public:
  enum class FlushType {
    FLUSH_TYPE_ALWAYS,
    FLUSH_TYPE_ALLOW_THREAD_LOCAL_DELAY,
  };

  IOBufQuicBatch(
      BatchWriterPtr&& batchWriter,
      bool threadLocal,
      folly::AsyncUDPSocket& sock,
      const folly::SocketAddress& peerAddress,
      QuicTransportStatsCallback* statsCallback,
      QuicClientConnectionState::HappyEyeballsState* happyEyeballsState);

  ~IOBufQuicBatch() = default;

  // returns true if it succeeds and false if the loop should end
  bool write(std::unique_ptr<folly::IOBuf>&& buf, size_t encodedSize);

  bool flush(
      FlushType flushType = FlushType::FLUSH_TYPE_ALLOW_THREAD_LOCAL_DELAY);

  FOLLY_ALWAYS_INLINE uint64_t getPktSent() const {
    return result_.packetsSent;
  }

  FOLLY_ALWAYS_INLINE BufQuicBatchResult getResult() const {
    return result_;
  }

 private:
  void reset();

  // flushes the internal buffers
  bool flushInternal();

  /**
   * Returns whether or not the errno can be retried later.
   */
  bool isRetriableError(int err);

  BatchWriterPtr batchWriter_;
  bool threadLocal_;
  folly::AsyncUDPSocket& sock_;
  const folly::SocketAddress& peerAddress_;
  QuicTransportStatsCallback* statsCallback_{nullptr};
  QuicClientConnectionState::HappyEyeballsState* happyEyeballsState_;
  BufQuicBatchResult result_;
};

} // namespace quic
