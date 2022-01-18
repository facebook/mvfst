/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/logging/FileQLogger.h>

#include <fstream>

#include <folly/json.h>

namespace quic {

void FileQLogger::setDcid(folly::Optional<ConnectionId> connID) {
  if (connID.hasValue()) {
    dcid = connID.value();
    if (streaming_) {
      setupStream();
    }
  }
}
void FileQLogger::setScid(folly::Optional<ConnectionId> connID) {
  if (connID.hasValue()) {
    scid = connID.value();
  }
}

void FileQLogger::setupStream() {
  // create the output file
  if (!dcid.hasValue()) {
    LOG(ERROR) << "Error: No dcid found";
    return;
  }
  endLine_ = prettyJson_ ? "\n" : "";
  auto extension = compress_ ? kCompressedQlogExtension : kQlogExtension;
  std::string outputPath =
      folly::to<std::string>(path_, "/", (dcid.value()).hex(), extension);
  try {
    writer_ = std::make_unique<folly::AsyncFileWriter>(outputPath);
  } catch (std::system_error err) {
    LOG(ERROR) << "Error creating qlog file. " << err.what();
    return;
  }
  if (compress_) {
    compressionCodec_ = folly::io::getStreamCodec(folly::io::CodecType::GZIP);
    compressionBuffer_ = folly::IOBuf::createCombined(kCompressionBufferSize);
  }

  // Create the base json
  auto qLog = prettyJson_ ? folly::toPrettyJson(toDynamicBase())
                          : folly::toJson(toDynamicBase());
  baseJson_ << qLog;

  // start copying from base to outputFile, stop at events
  baseJson_.seekg(0, baseJson_.beg);
  token_ = prettyJson_ ? "\"events\": [" : "\"events\":[";
  while (getline(baseJson_, eventLine_)) {
    pos_ = eventLine_.find(token_);
    if (pos_ == std::string::npos) {
      writeToStream(eventLine_ + endLine_);
    } else {
      // Found the token
      for (char c : eventLine_) {
        // get the amount of spaces each event should be padded
        if (c == ' ') {
          eventsPadding_ += ' ';
        } else {
          break;
        }
      }
      // write up to and including the token
      writeToStream(std::string(&eventLine_[0], pos_ + token_.size()));
      break;
    }
  }
}

void FileQLogger::writeToStream(folly::StringPiece message) {
  if (!writer_) {
    return;
  }
  if (compress_) {
    bool inputConsumed = false;
    while (!inputConsumed) {
      compressionBuffer_->clear();
      folly::ByteRange inputRange(message);
      auto outputRange = folly::MutableByteRange(
          compressionBuffer_->writableData(), compressionBuffer_->capacity());
      compressionCodec_->compressStream(inputRange, outputRange);
      // Output range has advanced to last compressed byte written
      auto outputLen = compressionBuffer_->capacity() - outputRange.size();
      // Input range has advanced to last uncompressed byte read
      inputConsumed = inputRange.empty();
      // Write compressed data to file
      writer_->writeMessage(folly::StringPiece(
          (const char*)compressionBuffer_->data(), outputLen));
    }
  } else {
    writer_->writeMessage(message);
  }
}

void FileQLogger::finishStream() {
  if (!writer_) {
    return;
  }
  // finish copying the line that was stopped on
  std::string unfinishedLine(
      &eventLine_[pos_ + token_.size()],
      eventLine_.size() - pos_ - token_.size() - (prettyJson_ ? 0 : 1));
  if (!prettyJson_) {
    writeToStream(unfinishedLine);
  } else {
    // copy all the remaining lines but the last one
    std::string previousLine = eventsPadding_ + unfinishedLine;
    while (getline(baseJson_, eventLine_)) {
      writeToStream(endLine_);
      writeToStream(previousLine);
      previousLine = eventLine_;
    }
  }
  writeToStream(folly::StringPiece(","));
  writeToStream(endLine_);

  // generate and add the summary
  auto summary = generateSummary(numEvents_, startTime_, endTime_);
  auto summaryJson =
      prettyJson_ ? folly::toPrettyJson(summary) : folly::toJson(summary);
  std::stringstream summaryBuffer;
  std::string line;
  writeToStream(
      prettyJson_ ? (basePadding_ + "\"summary\" : ") : "\"summary\":");
  summaryBuffer << summaryJson;
  std::string summaryPadding = "";
  // add padding to every line in the summary except the first
  while (getline(summaryBuffer, line)) {
    writeToStream(folly::to<std::string>(summaryPadding, line, endLine_));
    summaryPadding = basePadding_;
  }
  writeToStream(folly::StringPiece("}"));

  // Finalize compression frame
  if (compress_) {
    bool ended = false;
    while (!ended) {
      compressionBuffer_->clear();
      folly::ByteRange inputRange(folly::StringPiece(""));
      auto outputRange = folly::MutableByteRange(
          compressionBuffer_->writableData(), compressionBuffer_->capacity());
      ended = compressionCodec_->compressStream(
          inputRange, outputRange, folly::io::StreamCodec::FlushOp::END);
      auto outputLen = compressionBuffer_->capacity() - outputRange.size();
      writer_->writeMessage(folly::StringPiece(
          (const char*)compressionBuffer_->data(), outputLen));
    }
  }
}

void FileQLogger::handleEvent(std::unique_ptr<QLogEvent> event) {
  if (streaming_) {
    numEvents_++;
    startTime_ = (startTime_ == std::chrono::microseconds::zero())
        ? event->refTime
        : startTime_;
    endTime_ = event->refTime;
    auto eventJson = prettyJson_ ? folly::toPrettyJson(event->toDynamic())
                                 : folly::toJson(event->toDynamic());
    std::stringstream eventBuffer;
    std::string line;
    eventBuffer << eventJson;

    if (numEvents_ > 1) {
      writeToStream(folly::StringPiece(","));
    }

    // add padding to every line in the event
    while (getline(eventBuffer, line)) {
      writeToStream(endLine_);
      writeToStream(folly::to<std::string>(basePadding_, eventsPadding_, line));
    }

  } else {
    logs.push_back(std::move(event));
  }
}

void FileQLogger::addPacket(
    const RegularQuicPacket& regularPacket,
    uint64_t packetSize) {
  handleEvent(createPacketEvent(regularPacket, packetSize));
}

void FileQLogger::addPacket(
    const RegularQuicWritePacket& writePacket,
    uint64_t packetSize) {
  handleEvent(createPacketEvent(writePacket, packetSize));
}

void FileQLogger::addPacket(
    const VersionNegotiationPacket& versionPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  handleEvent(createPacketEvent(versionPacket, packetSize, isPacketRecvd));
}

void FileQLogger::addPacket(
    const RetryPacket& retryPacket,
    uint64_t packetSize,
    bool isPacketRecvd) {
  logs.push_back(createPacketEvent(retryPacket, packetSize, isPacketRecvd));
}

void FileQLogger::addConnectionClose(
    std::string error,
    std::string reason,
    bool drainConnection,
    bool sendCloseImmediately) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(std::make_unique<quic::QLogConnectionCloseEvent>(
      std::move(error),
      std::move(reason),
      drainConnection,
      sendCloseImmediately,
      refTime));
}

void FileQLogger::addTransportSummary(const TransportSummaryArgs& args) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogTransportSummaryEvent>(
      args.totalBytesSent,
      args.totalBytesRecvd,
      args.sumCurWriteOffset,
      args.sumMaxObservedOffset,
      args.sumCurStreamBufferLen,
      args.totalBytesRetransmitted,
      args.totalStreamBytesCloned,
      args.totalBytesCloned,
      args.totalCryptoDataWritten,
      args.totalCryptoDataRecvd,
      args.currentWritableBytes,
      args.currentConnFlowControl,
      args.totalPacketsSpuriouslyMarkedLost,
      args.finalPacketLossReorderingThreshold,
      args.finalPacketLossTimeReorderingThreshDividend,
      args.usedZeroRtt,
      args.quicVersion,
      args.dsrPacketCount,
      refTime));
}

void FileQLogger::addCongestionMetricUpdate(
    uint64_t bytesInFlight,
    uint64_t currentCwnd,
    std::string congestionEvent,
    std::string state,
    std::string recoveryState) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogCongestionMetricUpdateEvent>(
      bytesInFlight,
      currentCwnd,
      std::move(congestionEvent),
      std::move(state),
      std::move(recoveryState),
      refTime));
}

void FileQLogger::addBandwidthEstUpdate(
    uint64_t bytes,
    std::chrono::microseconds interval) {
  handleEvent(std::make_unique<quic::QLogBandwidthEstUpdateEvent>(
      bytes,
      interval,
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch())));
}

void FileQLogger::addAppLimitedUpdate() {
  handleEvent(std::make_unique<quic::QLogAppLimitedUpdateEvent>(
      true,
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch())));
}

void FileQLogger::addAppUnlimitedUpdate() {
  handleEvent(std::make_unique<quic::QLogAppLimitedUpdateEvent>(
      false,
      std::chrono::duration_cast<std::chrono::microseconds>(
          std::chrono::steady_clock::now().time_since_epoch())));
}
void FileQLogger::addPacingMetricUpdate(
    uint64_t pacingBurstSizeIn,
    std::chrono::microseconds pacingIntervalIn) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogPacingMetricUpdateEvent>(
      pacingBurstSizeIn, pacingIntervalIn, refTime));
}

void FileQLogger::addPacingObservation(
    std::string actual,
    std::string expect,
    std::string conclusion) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(std::make_unique<quic::QLogPacingObservationEvent>(
      std::move(actual), std::move(expect), std::move(conclusion), refTime));
}

void FileQLogger::addAppIdleUpdate(std::string idleEvent, bool idle) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogAppIdleUpdateEvent>(
      std::move(idleEvent), idle, refTime));
}

void FileQLogger::addPacketDrop(size_t packetSize, std::string dropReason) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogPacketDropEvent>(
      packetSize, std::move(dropReason), refTime));
}

void FileQLogger::addDatagramReceived(uint64_t dataLen) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogDatagramReceivedEvent>(dataLen, refTime));
}

void FileQLogger::addLossAlarm(
    PacketNum largestSent,
    uint64_t alarmCount,
    uint64_t outstandingPackets,
    std::string type) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogLossAlarmEvent>(
      largestSent, alarmCount, outstandingPackets, std::move(type), refTime));
}

void FileQLogger::addPacketsLost(
    PacketNum largestLostPacketNum,
    uint64_t lostBytes,
    uint64_t lostPackets) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogPacketsLostEvent>(
      largestLostPacketNum, lostBytes, lostPackets, refTime));
}

void FileQLogger::addTransportStateUpdate(std::string update) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogTransportStateUpdateEvent>(
      std::move(update), refTime));
}

void FileQLogger::addPacketBuffered(
    ProtectionType protectionType,
    uint64_t packetSize) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogPacketBufferedEvent>(
      protectionType, packetSize, refTime));
}

void FileQLogger::addMetricUpdate(
    std::chrono::microseconds latestRtt,
    std::chrono::microseconds mrtt,
    std::chrono::microseconds srtt,
    std::chrono::microseconds ackDelay) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogMetricUpdateEvent>(
      latestRtt, mrtt, srtt, ackDelay, refTime));
}

folly::dynamic FileQLogger::toDynamic() const {
  folly::dynamic dynamicObj = toDynamicBase();

  dynamicObj["summary"] =
      generateSummary(logs.size(), logs[0]->refTime, logs.back()->refTime);

  // convert stored logs into folly::Dynamic event array
  auto events = folly::dynamic::array();
  for (auto& event : logs) {
    events.push_back(event->toDynamic());
  }

  dynamicObj["traces"][0]["events"] = events;

  return dynamicObj;
}

folly::dynamic FileQLogger::toDynamicBase() const {
  folly::dynamic dynamicObj = folly::dynamic::object;
  dynamicObj[kQLogVersionField] = kQLogVersion;
  dynamicObj[kQLogTitleField] = kQLogTitle;
  dynamicObj[kQLogDescriptionField] = kQLogDescription;

  dynamicObj["traces"] = folly::dynamic::array();
  folly::dynamic dynamicTrace = folly::dynamic::object;

  dynamicTrace["vantage_point"] =
      folly::dynamic::object("type", vantagePointString(vantagePoint))(
          "name", vantagePointString(vantagePoint));
  dynamicTrace["title"] = kQLogTraceTitle;
  dynamicTrace["description"] = kQLogTraceDescription;
  dynamicTrace["configuration"] =
      folly::dynamic::object("time_offset", 0)("time_units", kQLogTimeUnits);

  std::string dcidStr = dcid.has_value() ? dcid.value().hex() : "";
  std::string scidStr = scid.has_value() ? scid.value().hex() : "";
  folly::dynamic commonFieldsObj = folly::dynamic::object;
  commonFieldsObj["reference_time"] = "0";
  commonFieldsObj["dcid"] = dcidStr;
  commonFieldsObj["scid"] = scidStr;
  commonFieldsObj["protocol_type"] = protocolType;
  dynamicTrace["common_fields"] = std::move(commonFieldsObj);

  dynamicTrace["events"] = folly::dynamic::array();
  dynamicTrace["event_fields"] =
      folly::dynamic::array("relative_time", "category", "event", "data");

  dynamicObj["traces"].push_back(dynamicTrace);

  return dynamicObj;
}

folly::dynamic FileQLogger::generateSummary(
    size_t numEvents,
    std::chrono::microseconds startTime,
    std::chrono::microseconds endTime) const {
  folly::dynamic summaryObj = folly::dynamic::object;
  summaryObj[kQLogTraceCountField] =
      1; // hardcoded, we only support 1 trace right now

  // max duration is calculated like this:
  // if there is <= 1 event, max_duration is 0
  // otherwise, it is the (time of the last event - time of the  first event)
  summaryObj["max_duration"] =
      (numEvents == 0) ? 0 : (endTime - startTime).count();
  summaryObj["total_event_count"] = numEvents;
  return summaryObj;
}

void FileQLogger::addStreamStateUpdate(
    quic::StreamId id,
    std::string update,
    folly::Optional<std::chrono::milliseconds> timeSinceStreamCreation) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(std::make_unique<quic::QLogStreamStateUpdateEvent>(
      id,
      std::move(update),
      std::move(timeSinceStreamCreation),
      vantagePoint,
      refTime));
}

void FileQLogger::addConnectionMigrationUpdate(bool intentionalMigration) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(std::make_unique<quic::QLogConnectionMigrationEvent>(
      intentionalMigration, vantagePoint, refTime));
}

void FileQLogger::addPathValidationEvent(bool success) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(std::make_unique<quic::QLogPathValidationEvent>(
      success, vantagePoint, refTime));
}

void FileQLogger::addPriorityUpdate(
    quic::StreamId streamId,
    uint8_t urgency,
    bool incremental) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(std::make_unique<quic::QLogPriorityUpdateEvent>(
      streamId, urgency, incremental, refTime));
}

void FileQLogger::outputLogsToFile(const std::string& path, bool prettyJson) {
  if (streaming_) {
    return;
  }
  if (!dcid.hasValue()) {
    LOG(ERROR) << "Error: No dcid found";
    return;
  }
  auto extension = compress_ ? kCompressedQlogExtension : kQlogExtension;
  std::string outputPath =
      folly::to<std::string>(path, "/", (dcid.value()).hex(), extension);

  std::ofstream fileObj(outputPath);
  if (fileObj) {
    auto qLog = prettyJson ? folly::toPrettyJson(toDynamic())
                           : folly::toJson(toDynamic());
    if (compress_) {
      try {
        auto gzipCodec = folly::io::getCodec(folly::io::CodecType::GZIP);
        auto compressed = gzipCodec->compress(qLog);
        fileObj << compressed;
      } catch (std::invalid_argument& ex) {
        LOG(ERROR) << "Failed to compress QLog. " << ex.what();
      }
    } else {
      fileObj << qLog;
    }
  } else {
    LOG(ERROR) << "Error: Can't write to provided path: " << path;
  }
  fileObj.close();
}
} // namespace quic
