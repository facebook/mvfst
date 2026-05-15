/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <cstdint>

#include <folly/SocketAddress.h>
#include <folly/io/IOBuf.h>

#include <quic/QuicException.h>
#include <quic/common/Expected.h>

namespace quic {

// Defined here (not in IoBufQuicBatch.h) so StateData.h can include this
// header without pulling in the IoBufQuicBatch → QuicBatchWriter → StateData
// include cycle.
struct BufQuicBatchResult {
  uint64_t packetsSent{0};
  uint64_t bytesSent{0};
};

/**
 * Abstract interface for sending fully-built, encrypted QUIC packets.
 *
 * The default path (conn.packetWriter == nullptr) calls IOBufQuicBatch
 * directly. When conn.packetWriter is set (ChainedMemory data path only),
 * writeConnectionDataToSocket dispatches through this interface instead.
 */
class QuicPacketWriter {
 public:
  virtual ~QuicPacketWriter() = default;

  // Called on the EventBase thread. Returns false → stop write loop
  // (backpressure, not an error). Returns unexpected → close connection.
  [[nodiscard]] virtual quic::Expected<bool, QuicError> write(
      BufPtr&& buf,
      size_t encodedSize,
      const folly::SocketAddress& peerAddr) = 0;

  [[nodiscard]] virtual quic::Expected<bool, QuicError> flush() = 0;

  // packetsSent counts packets handed to this writer (enqueued or sent inline).
  virtual BufQuicBatchResult getResult() const = 0;

  // Last retriable errno (EAGAIN/ENOBUFS) seen. Always 0 for async writers —
  // errno tracking is internal to their drain thread.
  virtual int getLastRetryableErrno() const {
    return 0;
  }
};

} // namespace quic
