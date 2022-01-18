/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/tools/tperf/TperfQLogger.h>

namespace quic {
namespace tperf {

TperfQLogger::TperfQLogger(VantagePoint vantagePoint, const std::string& path)
    : FileQLogger(
          vantagePoint,
          kHTTP3ProtocolType,
          path,
          true /* prettyJson*/,
          false /* streaming */),
      path_(path) {}

TperfQLogger::~TperfQLogger() {
  outputLogsToFile(path_, true /* prttyJson */);
}

void TperfQLogger::setPacingObserver(std::unique_ptr<PacingObserver> observer) {
  pacingObserver_ = std::move(observer);
}

void TperfQLogger::addPacket(
    const RegularQuicPacket& regularPacket,
    uint64_t packetSize) {
  FileQLogger::addPacket(regularPacket, packetSize);
}

void TperfQLogger::addPacket(
    const VersionNegotiationPacket& versionPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  FileQLogger::addPacket(versionPacket, packetSize, isPacketRecvd);
}

void TperfQLogger::addPacket(
    const RegularQuicWritePacket& packet,
    uint64_t size) {
  if (pacingObserver_) {
    pacingObserver_->onPacketSent();
  }
  FileQLogger::addPacket(packet, size);
}

void TperfQLogger::addPacingMetricUpdate(
    uint64_t pacingBurstSize,
    std::chrono::microseconds pacingInterval) {
  if (pacingObserver_) {
    pacingObserver_->onNewPacingRate(pacingBurstSize, pacingInterval);
  }
  FileQLogger::addPacingMetricUpdate(pacingBurstSize, pacingInterval);
}
} // namespace tperf
} // namespace quic
