/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/dynamic.h>
#include <quic/codec/Types.h>
#include <quic/logging/QLogger.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/logging/QLoggerTypes.h>

namespace quic {

class FileQLogger : public QLogger {
 public:
  std::vector<std::unique_ptr<QLogEvent>> logs;
  FileQLogger(std::string protocolTypeIn = kHTTP3ProtocolType.str()) {
    protocolType = std::move(protocolTypeIn);
  }
  ~FileQLogger() override = default;
  void addPacket(const RegularQuicPacket& regularPacket, uint64_t packetSize)
      override;
  void addPacket(
      const VersionNegotiationPacket& versionPacket,
      uint64_t packetSize,
      bool isPacketRecvd) override;
  void addPacket(const RegularQuicWritePacket& writePacket, uint64_t packetSize)
      override;
  void outputLogsToFile(const std::string& path, bool prettyJson);
  folly::dynamic toDynamic() const;
};
} // namespace quic
