/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicBatchWriter.h>
#ifndef MVFST_USE_LIBEV
#include <quic/api/QuicGsoBatchWriters.h>
#endif

namespace quic {

BatchWriterPtr makeGsoBatchWriter(uint32_t batchSize);
BatchWriterPtr makeGsoInPlaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn);
BatchWriterPtr makeSendmmsgGsoBatchWriter(uint32_t batchSize);

class BatchWriterFactory {
 public:
  static BatchWriterPtr makeBatchWriter(
      const quic::QuicBatchingMode& batchingMode,
      uint32_t batchSize,
      bool useThreadLocal,
      const std::chrono::microseconds& threadLocalDelay,
      DataPathType dataPathType,
      QuicConnectionStateBase& conn,
      bool gsoSupported);

 private:
  static BatchWriterPtr makeBatchWriterHelper(
      const quic::QuicBatchingMode& batchingMode,
      uint32_t batchSize,
      DataPathType dataPathType,
      QuicConnectionStateBase& conn,
      bool gsoSupported) {
    switch (batchingMode) {
      case quic::QuicBatchingMode::BATCHING_MODE_NONE:
        if (useSinglePacketInplaceBatchWriter(batchSize, dataPathType)) {
          return BatchWriterPtr(new SinglePacketInplaceBatchWriter(conn));
        }
        return BatchWriterPtr(new SinglePacketBatchWriter());
      case quic::QuicBatchingMode::BATCHING_MODE_GSO: {
        if (gsoSupported) {
          if (dataPathType == DataPathType::ChainedMemory) {
            return makeGsoBatchWriter(batchSize);
          }
          return makeGsoInPlaceBatchWriter(batchSize, conn);
        }
        // Fall through to Sendmmsg batching if gso is not supported.
      }
      case quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG:
        return BatchWriterPtr(new SendmmsgPacketBatchWriter(batchSize));
      case quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO: {
        if (gsoSupported) {
          return makeSendmmsgGsoBatchWriter(batchSize);
        }

        return BatchWriterPtr(new SendmmsgPacketBatchWriter(batchSize));
      }
        // no default so we can catch missing case at compile time
    }
    folly::assume_unreachable();
  }
};

} // namespace quic
