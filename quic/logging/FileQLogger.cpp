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

namespace quic {

void FileQLogger::addPacket(
    const RegularQuicPacket& regularPacket,
    uint64_t packetSize) {
  logs.push_back(createPacketEvent(regularPacket, packetSize));
}

void FileQLogger::addPacket(
    const RegularQuicWritePacket& writePacket,
    uint64_t packetSize) {
  logs.push_back(createPacketEvent(writePacket, packetSize));
}

void FileQLogger::addPacket(
    const VersionNegotiationPacket& versionPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  logs.push_back(createPacketEvent(versionPacket, packetSize, isPacketRecvd));
}

void FileQLogger::addConnectionClose(
    std::string error,
    std::string reason,
    bool drainConnection,
    bool sendCloseImmediately) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);
  logs.push_back(std::make_unique<quic::QLogConnectionCloseEvent>(
      std::move(error),
      std::move(reason),
      drainConnection,
      sendCloseImmediately,
      refTime));
}

void FileQLogger::addTransportSummary(
    uint64_t totalBytesSent,
    uint64_t totalBytesRecvd,
    uint64_t sumCurWriteOffset,
    uint64_t sumMaxObservedOffset,
    uint64_t sumCurStreamBufferLen,
    uint64_t totalBytesRetransmitted,
    uint64_t totalStreamBytesCloned,
    uint64_t totalBytesCloned,
    uint64_t totalCryptoDataWritten,
    uint64_t totalCryptoDataRecvd) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogTransportSummaryEvent>(
      totalBytesSent,
      totalBytesRecvd,
      sumCurWriteOffset,
      sumMaxObservedOffset,
      sumCurStreamBufferLen,
      totalBytesRetransmitted,
      totalStreamBytesCloned,
      totalBytesCloned,
      totalCryptoDataWritten,
      totalCryptoDataRecvd,
      refTime));
}

void FileQLogger::addCongestionMetricUpdate(
    uint64_t bytesInFlight,
    uint64_t currentCwnd,
    std::string congestionEvent,
    std::string state,
    std::string recoveryState) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogCongestionMetricUpdateEvent>(
      bytesInFlight,
      currentCwnd,
      std::move(congestionEvent),
      std::move(state),
      std::move(recoveryState),
      refTime));
}

void FileQLogger::addPacingMetricUpdate(
    uint64_t pacingBurstSizeIn,
    std::chrono::microseconds pacingIntervalIn) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogPacingMetricUpdateEvent>(
      pacingBurstSizeIn, pacingIntervalIn, refTime));
}

void FileQLogger::addAppIdleUpdate(std::string idleEvent, bool idle) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogAppIdleUpdateEvent>(
      std::move(idleEvent), idle, refTime));
}

void FileQLogger::addPacketDrop(size_t packetSize, std::string dropReason) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogPacketDropEvent>(
      packetSize, std::move(dropReason), refTime));
}

void FileQLogger::addDatagramReceived(uint64_t dataLen) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(
      std::make_unique<quic::QLogDatagramReceivedEvent>(dataLen, refTime));
}

void FileQLogger::addLossAlarm(
    PacketNum largestSent,
    uint64_t alarmCount,
    uint64_t outstandingPackets,
    std::string type) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogLossAlarmEvent>(
      largestSent, alarmCount, outstandingPackets, std::move(type), refTime));
}

void FileQLogger::addPacketsLost(
    PacketNum largestLostPacketNum,
    uint64_t lostBytes,
    uint64_t lostPackets) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogPacketsLostEvent>(
      largestLostPacketNum, lostBytes, lostPackets, refTime));
}

void FileQLogger::addTransportStateUpdate(std::string update) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogTransportStateUpdateEvent>(
      std::move(update), refTime));
}

void FileQLogger::addPacketBuffered(
    PacketNum packetNum,
    ProtectionType protectionType,
    uint64_t packetSize) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogPacketBufferedEvent>(
      packetNum, protectionType, packetSize, refTime));
}

void FileQLogger::addPacketAck(
    PacketNumberSpace packetNumSpace,
    PacketNum packetNum) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogPacketAckEvent>(
      packetNumSpace, packetNum, refTime));
}

void FileQLogger::addMetricUpdate(
    std::chrono::microseconds latestRtt,
    std::chrono::microseconds mrtt,
    std::chrono::microseconds srtt,
    std::chrono::microseconds ackDelay) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogMetricUpdateEvent>(
      latestRtt, mrtt, srtt, ackDelay, refTime));
}

folly::dynamic FileQLogger::toDynamic() const {
  folly::dynamic dynamicObj = folly::dynamic::object;
  dynamicObj[kQLogVersionField] = kQLogVersion;
  dynamicObj[kQLogTitleField] = kQLogTitle;
  dynamicObj[kQLogDescriptionField] = kQLogDescription;

  folly::dynamic summaryObj = folly::dynamic::object;
  summaryObj[kQLogTraceCountField] =
      1; // hardcoded, we only support 1 trace right now

  // max duration is calculated like this:
  // if there is <= 1 event, max_duration is 0
  // otherwise, it is the (time of the last event - time of the  first event)
  summaryObj["max_duration"] = (logs.size() == 0)
      ? 0
      : (logs.back()->refTime - logs[0]->refTime).count();
  summaryObj["max_outgoing_loss_rate"] = "";
  summaryObj["total_event_count"] = logs.size();
  dynamicObj["summary"] = summaryObj;

  dynamicObj["traces"] = folly::dynamic::array();
  folly::dynamic dynamicTrace = folly::dynamic::object;

  dynamicTrace["vantage_point"] =
      folly::dynamic::object("type", vantagePoint)("name", vantagePoint);
  dynamicTrace["title"] = kQLogTraceTitle;
  dynamicTrace["description"] = kQLogTraceDescription;
  dynamicTrace["configuration"] =
      folly::dynamic::object("time_offset", 0)("time_units", kQLogTimeUnits);

  std::string dcidStr = dcid.hasValue() ? dcid.value().hex() : "";
  std::string scidStr = scid.hasValue() ? scid.value().hex() : "";
  folly::dynamic commonFieldsObj = folly::dynamic::object;
  commonFieldsObj["reference_time"] = "0";
  commonFieldsObj["dcid"] = dcidStr;
  commonFieldsObj["scid"] = scidStr;
  commonFieldsObj["protocol_type"] = protocolType;
  dynamicTrace["common_fields"] = std::move(commonFieldsObj);

  // convert stored logs into folly::Dynamic event array
  auto events = folly::dynamic::array();
  for (auto& event : logs) {
    events.push_back(event->toDynamic());
  }
  dynamicTrace["events"] = events;
  dynamicTrace["event_fields"] = folly::dynamic::array(
      "relative_time", "CATEGORY", "EVENT_TYPE", "TRIGGER", "DATA");

  dynamicObj["traces"].push_back(dynamicTrace);
  return dynamicObj;
}

void FileQLogger::addStreamStateUpdate(quic::StreamId id, std::string update) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now() - refTimePoint);

  logs.push_back(std::make_unique<quic::QLogStreamStateUpdateEvent>(
      id, std::move(update), refTime));
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
