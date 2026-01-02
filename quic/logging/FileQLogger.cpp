/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/logging/FileQLogger.h>

#include <fstream>
#include <vector>

#include <folly/json/json.h> // @manual=//folly:dynamic

namespace quic {

void FileQLogger::setDcid(Optional<ConnectionId> connID) {
  if (connID.has_value()) {
    dcid = connID.value();
    if (streaming_) {
      setupStream();
    }
  }
}

void FileQLogger::setScid(Optional<ConnectionId> connID) {
  if (connID.has_value()) {
    scid = connID.value();
  }
}

void FileQLogger::setupStream() {
  // create the output file
  if (!dcid.has_value()) {
    MVLOG_ERROR << "Error: No dcid found";
    return;
  }
  numEvents_ = 0;
  startTime_ = std::chrono::microseconds::zero();
  endLine_ = prettyJson_ ? "\n" : "";
  auto extension = compress_ ? kCompressedQlogExtension : kQlogExtension;
  std::string outputPath =
      fmt::format("{}/{}{}", path_, (dcid.value()).hex(), extension);
  try {
    writer_ = std::make_unique<folly::AsyncFileWriter>(outputPath);
  } catch (const std::system_error& err) {
    MVLOG_ERROR << "Error creating qlog file. " << err.what();
    return;
  }
  if (compress_) {
    compressionCodec_ =
        folly::compression::getStreamCodec(folly::compression::CodecType::GZIP);
    compressionBuffer_ = BufHelpers::createCombined(kCompressionBufferSize);
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
      ByteRange inputRange(message);
      auto outputRange = MutableByteRange(
          compressionBuffer_->writableData(), compressionBuffer_->capacity());
      compressionCodec_->compressStream(inputRange, outputRange);
      // Output range has advanced to last compressed byte written
      auto outputLen = compressionBuffer_->capacity() - outputRange.size();
      // Input range has advanced to last uncompressed byte read
      inputConsumed = inputRange.empty();
      // Write compressed data to file
      writer_->writeMessage(
          folly::StringPiece(
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

    writeToStream(folly::StringPiece("}"));
  } else {
    std::vector<std::string> remainingLines;
    remainingLines.push_back(eventsPadding_ + unfinishedLine);

    while (getline(baseJson_, eventLine_)) {
      remainingLines.push_back(eventLine_);
    }

    for (size_t i = 0; i < remainingLines.size(); ++i) {
      if (i > 0) {
        writeToStream(endLine_);
      }
      writeToStream(remainingLines[i]);
    }
  }

  // Finalize compression frame
  if (compress_) {
    bool ended = false;
    while (!ended) {
      compressionBuffer_->clear();
      ByteRange inputRange(folly::StringPiece(""));
      auto outputRange = MutableByteRange(
          compressionBuffer_->writableData(), compressionBuffer_->capacity());
      ended = compressionCodec_->compressStream(
          inputRange,
          outputRange,
          folly::compression::StreamCodec::FlushOp::END);
      auto outputLen = compressionBuffer_->capacity() - outputRange.size();
      writer_->writeMessage(
          folly::StringPiece(
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

    bool firstLine = true;
    while (getline(eventBuffer, line)) {
      if (firstLine) {
        if (numEvents_ > 1) {
          writeToStream(folly::StringPiece(","));
        }
        writeToStream(endLine_);
        firstLine = false;
      } else {
        writeToStream(endLine_);
      }
      writeToStream(fmt::format("{}{}{}", basePadding_, eventsPadding_, line));
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
  handleEvent(
      std::make_unique<quic::QLogConnectionCloseEvent>(
          std::move(error),
          std::move(reason),
          drainConnection,
          sendCloseImmediately,
          refTime));
}

void FileQLogger::addTransportSummary(const TransportSummaryArgs& args) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogTransportSummaryEvent>(
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
          args.initialPacketsReceived,
          args.uniqueInitialCryptoFramesReceived,
          args.timeUntilLastInitialCryptoFrameReceived,
          args.alpn,
          args.namedGroup,
          args.pskType,
          args.echStatus,
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

  handleEvent(
      std::make_unique<quic::QLogCongestionMetricUpdateEvent>(
          bytesInFlight,
          currentCwnd,
          std::move(congestionEvent),
          std::move(state),
          std::move(recoveryState),
          refTime));
}

void FileQLogger::addCongestionStateUpdate(
    Optional<std::string> oldState,
    std::string newState,
    Optional<std::string> trigger) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogCongestionStateUpdateEvent>(
          std::move(oldState),
          std::move(newState),
          std::move(trigger),
          refTime));
}

void FileQLogger::addBandwidthEstUpdate(
    uint64_t bytes,
    std::chrono::microseconds interval) {
  handleEvent(
      std::make_unique<quic::QLogBandwidthEstUpdateEvent>(
          bytes,
          interval,
          std::chrono::duration_cast<std::chrono::microseconds>(
              std::chrono::steady_clock::now().time_since_epoch())));
}

void FileQLogger::addAppLimitedUpdate() {
  handleEvent(
      std::make_unique<quic::QLogAppLimitedUpdateEvent>(
          true,
          std::chrono::duration_cast<std::chrono::microseconds>(
              std::chrono::steady_clock::now().time_since_epoch())));
}

void FileQLogger::addAppUnlimitedUpdate() {
  handleEvent(
      std::make_unique<quic::QLogAppLimitedUpdateEvent>(
          false,
          std::chrono::duration_cast<std::chrono::microseconds>(
              std::chrono::steady_clock::now().time_since_epoch())));
}

void FileQLogger::addPacingMetricUpdate(
    uint64_t pacingBurstSizeIn,
    std::chrono::microseconds pacingIntervalIn) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogPacingMetricUpdateEvent>(
          pacingBurstSizeIn, pacingIntervalIn, refTime));
}

void FileQLogger::addPacingObservation(
    std::string actual,
    std::string expect,
    std::string conclusion) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(
      std::make_unique<quic::QLogPacingObservationEvent>(
          std::move(actual),
          std::move(expect),
          std::move(conclusion),
          refTime));
}

void FileQLogger::addAppIdleUpdate(std::string idleEvent, bool idle) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogAppIdleUpdateEvent>(
          std::move(idleEvent), idle, refTime));
}

void FileQLogger::addPacketDrop(size_t packetSize, std::string dropReason) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogPacketDropEvent>(
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

  handleEvent(
      std::make_unique<quic::QLogLossAlarmEvent>(
          largestSent,
          alarmCount,
          outstandingPackets,
          std::move(type),
          refTime));
}

void FileQLogger::addPacketsLost(
    PacketNum largestLostPacketNum,
    uint64_t lostBytes,
    uint64_t lostPackets) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogPacketsLostEvent>(
          largestLostPacketNum, lostBytes, lostPackets, refTime));
}

void FileQLogger::addTransportStateUpdate(std::string update) {
  static const std::unordered_set<std::string> validStates = {
      "attempted",
      "handshake_started",
      "handshake_complete",
      "closed",
      "peer_validated",
      "early_write",
      "handshake_confirmed",
      "closing",
      "draining"};

  if (validStates.find(update) == validStates.end()) {
    return;
  }

  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogTransportStateUpdateEvent>(
          std::move(update), refTime));
}

void FileQLogger::addPacketBuffered(
    ProtectionType protectionType,
    uint64_t packetSize) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogPacketBufferedEvent>(
          protectionType, packetSize, refTime));
}

void FileQLogger::addMetricUpdate(
    std::chrono::microseconds latestRtt,
    std::chrono::microseconds mrtt,
    std::chrono::microseconds srtt,
    std::chrono::microseconds ackDelay,
    Optional<std::chrono::microseconds> rttVar,
    Optional<uint64_t> congestionWindow,
    Optional<uint64_t> bytesInFlight,
    Optional<uint64_t> ssthresh,
    Optional<uint64_t> packetsInFlight,
    Optional<uint64_t> pacingRateBytesPerSec,
    Optional<uint32_t> ptoCount) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogMetricUpdateEvent>(
          latestRtt,
          mrtt,
          srtt,
          ackDelay,
          refTime,
          rttVar,
          congestionWindow,
          bytesInFlight,
          ssthresh,
          packetsInFlight,
          pacingRateBytesPerSec,
          ptoCount));
}

folly::dynamic FileQLogger::toDynamic() const {
  folly::dynamic qlogFile = toDynamicBase();

  auto events = folly::dynamic::array();
  for (auto& event : logs) {
    events.push_back(event->toDynamic());
  }

  qlogFile["traces"][0]["events"] = events;

  return qlogFile;
}

folly::dynamic FileQLogger::toDynamicBase() const {
  folly::dynamic qlogFile = folly::dynamic::object();

  qlogFile["description"] = kQLogDescription;
  qlogFile["file_schema"] = kQLogFileSchemaURI;
  qlogFile["serialization_format"] = kQLogSerializationFormat;
  qlogFile["title"] = kQLogTitle;

  folly::dynamic trace = folly::dynamic::object();
  trace["title"] = kQLogTraceTitle;
  trace["description"] = kQLogTraceDescription;

  auto vpInfo = createVantagePoint(vantagePoint, "");
  trace["vantage_point"] = vpInfo.toDynamic();

  trace["event_schemas"] =
      folly::dynamic::array(kQLogEventSchemaURI, kQLogMvfstEventSchemaURI);

  folly::dynamic commonFieldsDyn = folly::dynamic::object();
  commonFieldsDyn["odcid"] = dcid.has_value() ? dcid.value().hex() : "";

  if (!protocolType.empty()) {
    commonFieldsDyn["protocol_type"] = protocolType;
  }
  folly::dynamic refTime = folly::dynamic::object();
  refTime["clock_type"] = kQLogClockTypeMonotonic;
  refTime["epoch"] = "unknown";
  commonFieldsDyn["reference_time"] = std::move(refTime);
  commonFieldsDyn["time_format"] = kQLogTimeFormatRelativeToEpoch;

  commonFieldsDyn["scid"] = scid.has_value() ? scid.value().hex() : "";

  trace["common_fields"] = std::move(commonFieldsDyn);

  trace["events"] = folly::dynamic::array();

  qlogFile["traces"] = folly::dynamic::array();
  qlogFile["traces"].push_back(std::move(trace));

  return qlogFile;
}

folly::dynamic FileQLogger::generateSummary(
    size_t numEvents,
    std::chrono::microseconds startTime,
    std::chrono::microseconds endTime) const {
  folly::dynamic summaryObj = folly::dynamic::object();
  summaryObj[kQLogTraceCountField] =
      1; // hardcoded, we only support 1 trace right now

  // max duration is calculated like this:
  // if there is <= 1 event, max_duration is 0
  // otherwise, it is the (time of the last event - time of the  first event)
  summaryObj["max_duration"] =
      (numEvents <= 1) ? 0 : (endTime - startTime).count();
  summaryObj["total_event_count"] = numEvents;
  return summaryObj;
}

void FileQLogger::addStreamStateUpdate(
    quic::StreamId id,
    std::string update,
    Optional<std::chrono::milliseconds> timeSinceStreamCreation) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());

  handleEvent(
      std::make_unique<quic::QLogStreamStateUpdateEvent>(
          id,
          std::move(update),
          std::move(timeSinceStreamCreation),
          vantagePoint,
          refTime));
}

void FileQLogger::addConnectionMigrationUpdate(bool intentionalMigration) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(
      std::make_unique<quic::QLogConnectionMigrationEvent>(
          intentionalMigration, vantagePoint, refTime));
}

void FileQLogger::addPathValidationEvent(bool success) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(
      std::make_unique<quic::QLogPathValidationEvent>(
          success, vantagePoint, refTime));
}

void FileQLogger::addPriorityUpdate(
    quic::StreamId streamId,
    PriorityQueue::PriorityLogFields priority) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(
      std::make_unique<quic::QLogPriorityUpdateEvent>(
          streamId, std::move(priority), refTime));
}

void FileQLogger::addL4sWeightUpdate(
    double l4sWeight,
    uint32_t newEct1,
    uint32_t newCe) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(
      std::make_unique<quic::QLogL4sWeightUpdateEvent>(
          l4sWeight, newEct1, newCe, refTime));
}

void FileQLogger::addNetworkPathModelUpdate(
    uint64_t inflightHi,
    uint64_t inflightLo,
    uint64_t bandwidthHiBytes,
    std::chrono::microseconds bandwidthHiInterval,
    uint64_t bandwidthLoBytes,
    std::chrono::microseconds bandwidthLoInterval) {
  auto refTime = std::chrono::duration_cast<std::chrono::microseconds>(
      std::chrono::steady_clock::now().time_since_epoch());
  handleEvent(
      std::make_unique<quic::QLogNetworkPathModelUpdateEvent>(
          inflightHi,
          inflightLo,
          bandwidthHiBytes,
          bandwidthHiInterval,
          bandwidthLoBytes,
          bandwidthLoInterval,
          refTime));
}

void FileQLogger::outputLogsToFile(const std::string& path, bool prettyJson) {
  if (streaming_) {
    return;
  }
  if (!dcid.has_value()) {
    MVLOG_ERROR << "Error: No dcid found";
    return;
  }
  auto extension = compress_ ? kCompressedQlogExtension : kQlogExtension;
  std::string outputPath =
      fmt::format("{}/{}{}", path, (dcid.value()).hex(), extension);

  std::ofstream fileObj(outputPath);
  if (fileObj) {
    auto qLog = prettyJson ? folly::toPrettyJson(toDynamic())
                           : folly::toJson(toDynamic());
    if (compress_) {
      try {
        auto gzipCodec =
            folly::compression::getCodec(folly::compression::CodecType::GZIP);
        auto compressed = gzipCodec->compress(qLog);
        fileObj << compressed;
      } catch (std::invalid_argument& ex) {
        MVLOG_ERROR << "Failed to compress QLog. " << ex.what();
      }
    } else {
      fileObj << qLog;
    }
  } else {
    MVLOG_ERROR << "Error: Can't write to provided path: " << path;
  }
  fileObj.close();
}
} // namespace quic
