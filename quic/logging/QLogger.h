/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/logging/QLoggerTypes.h>

namespace quic {

class QLogger {
 public:
  folly::Optional<ConnectionId> dcid;
  folly::Optional<ConnectionId> scid;
  std::chrono::steady_clock::time_point refTimePoint{
      std::chrono::steady_clock::now()};
  std::string protocolType;
  QLogger() = default;
  virtual ~QLogger() = default;
  virtual void addPacket(
      const RegularQuicPacket& regularPacket,
      uint64_t packetSize) = 0;
  virtual void addPacket(
      const VersionNegotiationPacket& versionPacket,
      uint64_t packetSize,
      bool isPacketRecvd) = 0;
  virtual void addPacket(
      const RegularQuicWritePacket& writePacket,
      uint64_t packetSize) = 0;
  virtual void addConnectionClose(
      std::string error,
      std::string reason,
      bool drainConnection,
      bool sendCloseImmediately) = 0;
  virtual void addTransportSummary(
      uint64_t totalBytesSent,
      uint64_t totalBytesRecvd,
      uint64_t sumCurWriteOffset,
      uint64_t sumMaxObservedOffset,
      uint64_t sumCurStreamBufferLen,
      uint64_t totalBytesRetransmitted,
      uint64_t totalStreamBytesCloned,
      uint64_t totalBytesCloned,
      uint64_t totalCryptoDataWritten,
      uint64_t totalCryptoDataRecvd) = 0;
  virtual void addCongestionMetricUpdate(
      uint64_t bytesInFlight,
      uint64_t currentCwnd,
      std::string congestionEvent,
      std::string state = "",
      std::string recoveryState = "") = 0;
  std::unique_ptr<QLogPacketEvent> createPacketEvent(
      const RegularQuicPacket& regularPacket,
      uint64_t packetSize);

  std::unique_ptr<QLogPacketEvent> createPacketEvent(
      const RegularQuicWritePacket& writePacket,
      uint64_t packetSize);

  std::unique_ptr<QLogVersionNegotiationEvent> createPacketEvent(
      const VersionNegotiationPacket& versionPacket,
      uint64_t packetSize,
      bool isPacketRecvd);
};
} // namespace quic
