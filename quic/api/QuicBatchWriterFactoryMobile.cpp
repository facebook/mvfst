/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriterFactory.h>

namespace quic {

// BatchWriterDeleter
void BatchWriterDeleter::operator()(BatchWriter* batchWriter) {
  delete batchWriter;
}

BatchWriterPtr makeGsoBatchWriter(uint32_t) {
  LOG(FATAL) << "not implemented for mobile";
  return nullptr;
}

BatchWriterPtr makeGsoInPlaceBatchWriter(uint32_t, QuicConnectionStateBase&) {
  LOG(FATAL) << "not implemented for mobile";
  return nullptr;
}

BatchWriterPtr makeSendmmsgGsoBatchWriter(uint32_t) {
  LOG(FATAL) << "not implemented for mobile";
  return nullptr;
}

BatchWriterPtr BatchWriterFactory::makeBatchWriter(
    const quic::QuicBatchingMode& batchingMode,
    uint32_t batchSize,
    bool /* useThreadLocal */,
    const std::chrono::microseconds& /* threadLocalDelay */,
    DataPathType dataPathType,
    QuicConnectionStateBase& conn,
    bool gsoSupported) {
  return makeBatchWriterHelper(
      batchingMode, batchSize, dataPathType, conn, gsoSupported);
}

} // namespace quic
