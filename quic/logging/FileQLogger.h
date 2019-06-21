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
#include <quic/logging/QLoggerTypes.h>

namespace quic {

class FileQLogger : public QLogger {
 public:
  std::vector<std::unique_ptr<QLogEvent>> logs;
  FileQLogger() = default;
  ~FileQLogger() override = default;
  void add(const RegularQuicPacket& regularPacket, uint64_t packetSize)
      override;
  void add(
      const VersionNegotiationPacket& versionPacket,
      uint64_t packetSize,
      bool isPacketRecvd) override;
  void add(const RegularQuicWritePacket& writePacket, uint64_t packetSize)
      override;
  folly::dynamic toDynamic() const;
};
} // namespace quic
