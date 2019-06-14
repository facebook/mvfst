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
#include <quic/logging/QLoggerTypes.h>
#include <memory>
#include <string>
#include <vector>

namespace quic {

class QLogger {
 public:
  std::vector<std::unique_ptr<QLogEvent>> logs;

  ~QLogger() = default;
  QLogger() = default;

  void add(const RegularQuicPacket& regularPacket, uint64_t packetSize);

  void add(
      const VersionNegotiationPacket& versionPacket,
      uint64_t packetSize,
      bool isPacketRecvd);

  void add(const RegularQuicWritePacket& writePacket, uint64_t packetSize);

  folly::dynamic toDynamic();

 private:
  folly::dynamic d;
};

} // namespace quic
