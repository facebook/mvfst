/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/logging/FileQLogger.h>
#include <quic/tools/tperf/PacingObserver.h>

namespace quic {
namespace tperf {
class TperfQLogger : public FileQLogger {
 public:
  explicit TperfQLogger(VantagePoint vantagePoint, const std::string& path);
  virtual ~TperfQLogger() override;

  void setPacingObserver(std::unique_ptr<PacingObserver> pacingObserver);

  void addPacingMetricUpdate(
      uint64_t pacingBurstSize,
      std::chrono::microseconds pacingInterval) override;

  void addPacket(const RegularQuicPacket& regularPacket, uint64_t packetSize)
      override;
  void addPacket(
      const VersionNegotiationPacket& versionPacket,
      uint64_t packetSize,
      bool isPacketRecvd) override;

  void addPacket(
      const RegularQuicWritePacket& regularPacket,
      uint64_t packetSize) override;

 private:
  std::string path_;
  std::unique_ptr<PacingObserver> pacingObserver_;
};
} // namespace tperf
} // namespace quic
