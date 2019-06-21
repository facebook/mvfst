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
  QLogger() = default;
  virtual ~QLogger() = default;
  virtual void add(
      const RegularQuicPacket& regularPacket,
      uint64_t packetSize) = 0;
  virtual void add(
      const VersionNegotiationPacket& versionPacket,
      uint64_t packetSize,
      bool isPacketRecvd) = 0;
  virtual void add(
      const RegularQuicWritePacket& writePacket,
      uint64_t packetSize) = 0;
};

std::unique_ptr<QLogPacketEvent> createPacketEvent(
    const RegularQuicPacket& regularPacket,
    uint64_t packetSize);

std::unique_ptr<QLogPacketEvent> createPacketEvent(
    const RegularQuicWritePacket& writePacket,
    uint64_t packetSize);

std::unique_ptr<QLogVersionNegotiationEvent> createPacketEvent(
    const VersionNegotiationPacket& versionPacket,
    size_t packetSize,
    bool isPacketRecvd);

} // namespace quic
