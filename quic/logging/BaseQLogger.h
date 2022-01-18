/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/logging/QLogger.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QLoggerTypes.h>

namespace quic {

class BaseQLogger : public QLogger {
 public:
  explicit BaseQLogger(VantagePoint vantagePointIn, std::string protocolTypeIn)
      : QLogger(vantagePointIn, std::move(protocolTypeIn)) {}

  ~BaseQLogger() override = default;

 protected:
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

  std::unique_ptr<QLogRetryEvent> createPacketEvent(
      const RetryPacket& retryPacket,
      uint64_t packetSize,
      bool isPacketRecvd);
};
} // namespace quic
