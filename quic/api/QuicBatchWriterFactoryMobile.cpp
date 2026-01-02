/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/common/MvfstLogging.h>

namespace quic {

// BatchWriterDeleter
void BatchWriterDeleter::operator()(BatchWriter* batchWriter) {
  delete batchWriter;
}

BatchWriterPtr makeGsoBatchWriter(uint32_t) {
  MVLOG_FATAL << "GSO batch writer not implemented for mobile";
  return nullptr;
}

BatchWriterPtr makeGsoInPlaceBatchWriter(uint32_t, QuicConnectionStateBase&) {
  MVLOG_FATAL << "GSO inplace batch writer not implemented for mobile";
  return nullptr;
}

BatchWriterPtr makeSendmmsgGsoBatchWriter(uint32_t) {
  MVLOG_FATAL << "Sendmmsg GSO batch writer not implemented for mobile";
  return nullptr;
}

BatchWriterPtr makeSendmmsgInplaceGsoInplaceBatchWriter(
    uint32_t,
    QuicConnectionStateBase&) {
  MVLOG_FATAL << "Sendmmsg GSO inplace batch writer not implemented for mobile";
  return nullptr;
}

BatchWriterPtr BatchWriterFactory::makeBatchWriter(
    const quic::QuicBatchingMode& batchingMode,
    uint32_t batchSize,
    bool /* enableBackpressure */,
    DataPathType dataPathType,
    QuicConnectionStateBase& conn,
    bool /* gsoSupported */) {
  // Mobile only supports single-packet writers
  // GSO and sendmmsg batching are not available on mobile platforms
  switch (batchingMode) {
    case quic::QuicBatchingMode::BATCHING_MODE_NONE:
    default:
      if (useSinglePacketInplaceBatchWriter(batchSize, dataPathType)) {
        return BatchWriterPtr(new SinglePacketInplaceBatchWriter(conn));
      }
      return BatchWriterPtr(new SinglePacketBatchWriter());
  }
}

} // namespace quic
