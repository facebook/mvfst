/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
#include <quic/logging/FileQLogger.h>

#include <fstream>

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
    uint64_t packetSize,
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

void FileQLogger::outputLogsToFile(const std::string& path, bool prettyJson) {
  if (!dcid.hasValue()) {
    LOG(ERROR) << "Error: No dcid found";
    return;
  }
  std::string outputPath =
      folly::to<std::string>(path, "/", (dcid.value()).hex(), ".qlog");
  std::ofstream fileObj(outputPath);
  if (fileObj) {
    LOG(INFO) << "Logging QLogger JSON to file: " << outputPath;
    auto qLog = prettyJson ? folly::toPrettyJson(toDynamic())
                           : folly::toJson(toDynamic());
    fileObj << qLog;
  } else {
    LOG(ERROR) << "Error: Can't write to provided path: " << path;
  }
  fileObj.close();
}

} // namespace quic
