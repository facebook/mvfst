/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicBatchWriter.h>

namespace quic {

BatchWriterPtr makeGsoBatchWriter(uint32_t batchSize);
BatchWriterPtr makeGsoInPlaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn);
BatchWriterPtr makeSendmmsgGsoBatchWriter(uint32_t batchSize);
BatchWriterPtr makeSendmmsgInplaceGsoInplaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn);

class BatchWriterFactory {
 public:
  static BatchWriterPtr makeBatchWriter(
      const quic::QuicBatchingMode& batchingMode,
      uint32_t batchSize,
      bool enableBackpressure,
      DataPathType dataPathType,
      QuicConnectionStateBase& conn,
      bool gsoSupported);
};

} // namespace quic
