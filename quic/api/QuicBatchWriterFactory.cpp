/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriterFactory.h>
#include <quic/common/events/QuicEventBase.h>

namespace quic {

// BatchWriterDeleter
void BatchWriterDeleter::operator()(BatchWriter* batchWriter) {
  delete batchWriter;
}

BatchWriterPtr makeGsoBatchWriter(uint32_t batchSize) {
  return BatchWriterPtr(new GSOPacketBatchWriter(batchSize));
}

BatchWriterPtr makeGsoInPlaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn) {
  return BatchWriterPtr(new GSOInplacePacketBatchWriter(conn, batchSize));
}

BatchWriterPtr makeSendmmsgGsoBatchWriter(uint32_t batchSize) {
  return BatchWriterPtr(new SendmmsgGSOPacketBatchWriter(batchSize));
}

BatchWriterPtr BatchWriterFactory::makeBatchWriter(
    const quic::QuicBatchingMode& batchingMode,
    uint32_t batchSize,
    bool enableBackpressure,
    DataPathType dataPathType,
    QuicConnectionStateBase& conn,
    bool gsoSupported) {
  return makeBatchWriterHelper(
      batchingMode,
      batchSize,
      enableBackpressure,
      dataPathType,
      conn,
      gsoSupported);
}

} // namespace quic
