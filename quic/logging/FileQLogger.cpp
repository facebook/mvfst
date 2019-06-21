/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
#include <quic/logging/FileQLogger.h>

#include <folly/json.h>
#include <quic/logging/QLogger.h>

namespace quic {

void FileQLogger::add(
    const RegularQuicPacket& regularPacket,
    uint64_t packetSize) {
  logs.push_back(createPacketEvent(regularPacket, packetSize));
}

void FileQLogger::add(
    const RegularQuicWritePacket& writePacket,
    uint64_t packetSize) {
  logs.push_back(createPacketEvent(writePacket, packetSize));
}

void FileQLogger::add(
    const VersionNegotiationPacket& versionPacket,
    size_t packetSize,
    bool isPacketRecvd) {
  logs.push_back(createPacketEvent(versionPacket, packetSize, isPacketRecvd));
}

folly::dynamic FileQLogger::toDynamic() const {
  folly::dynamic d = folly::dynamic::object;
  d["traces"] = folly::dynamic::array();
  folly::dynamic dTrace = folly::dynamic::object;

  // convert stored logs into folly::Dynamic event array
  auto events = folly::dynamic::array();
  for (auto& event : logs) {
    events.push_back(event->toDynamic());
  }
  dTrace["events"] = events;
  dTrace["event_fields"] =
      folly::dynamic::array("CATEGORY", "EVENT_TYPE", "TRIGGER", "DATA");

  d["traces"].push_back(dTrace);
  return d;
}

} // namespace quic
