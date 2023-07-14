/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicBatchWriter.h>
#include <quic/api/QuicGsoBatchWriters.h>

namespace quic {

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
};

} // namespace quic
