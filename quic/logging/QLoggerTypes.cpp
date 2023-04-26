/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/logging/QLoggerTypes.h>

#include <quic/QuicException.h>
#include <quic/logging/QLoggerConstants.h>

namespace quic {

folly::dynamic PaddingFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::PADDING);
  d["num_frames"] = numFrames;
  return d;
}

folly::dynamic NewTokenFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::NEW_TOKEN);
  d["token"] = token;
  return d;
}

folly::dynamic RstStreamFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::RST_STREAM);
  d["stream_id"] = streamId;
  d["error_code"] = errorCode;
  d["offset"] = offset;
  return d;
}

folly::dynamic ConnectionCloseFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();

  auto isTransportErrorCode = errorCode.asTransportErrorCode();
  auto isApplicationErrorCode = errorCode.asApplicationErrorCode();
  auto isLocalErrorCode = errorCode.asLocalErrorCode();

  if (isTransportErrorCode || isLocalErrorCode) {
    d["frame_type"] = toQlogString(FrameType::CONNECTION_CLOSE);
  } else if (isApplicationErrorCode) {
    d["frame_type"] = toQlogString(FrameType::CONNECTION_CLOSE_APP_ERR);
  }

  d["error_code"] = toString(errorCode);
  d["reason_phrase"] = reasonPhrase;
  d["closing_frame_type"] = toString(closingFrameType);
  return d;
}

folly::dynamic MaxDataFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::MAX_DATA);
  d["maximum_data"] = maximumData;
  return d;
}

folly::dynamic MaxStreamDataFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::MAX_STREAM_DATA);
  d["stream_id"] = streamId;
  d["maximum_data"] = maximumData;
  return d;
}

folly::dynamic MaxStreamsFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  FrameType type;
  if (isForBidirectional) {
    type = FrameType::MAX_STREAMS_BIDI;
  } else {
    type = FrameType::MAX_STREAMS_UNI;
  }
  d["frame_type"] = toString(type);
  d["max_streams"] = maxStreams;
  return d;
}

folly::dynamic StreamsBlockedFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  FrameType type;
  if (isForBidirectional) {
    type = FrameType::STREAMS_BLOCKED_BIDI;
  } else {
    type = FrameType::STREAMS_BLOCKED_UNI;
  }
  d["frame_type"] = toString(type);
  d["stream_limit"] = streamLimit;
  return d;
}

folly::dynamic PingFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::PING);
  return d;
}

folly::dynamic DataBlockedFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::DATA_BLOCKED);
  d["data_limit"] = dataLimit;
  return d;
}

folly::dynamic KnobFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::KNOB);
  d["knob_space"] = knobSpace;
  d["knob_id"] = knobId;
  d["knob_blob_len"] = knobBlobLen;
  return d;
}

folly::dynamic AckFrequencyFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::ACK_FREQUENCY);
  d["sequence_number"] = sequenceNumber;
  d["packet_tolerance"] = packetTolerance;
  d["update_max_ack_delay"] = updateMaxAckDelay;
  d["reorder_threshold"] = reorderThreshold;
  return d;
}

folly::dynamic ImmediateAckFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::IMMEDIATE_ACK);
  return d;
}

folly::dynamic StreamDataBlockedFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::STREAM_DATA_BLOCKED);
  d["stream_id"] = streamId;
  d["data_limit"] = dataLimit;
  return d;
}

folly::dynamic StreamFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["offset"] = offset;
  d["length"] = len;
  d["fin"] = fin;
  d["stream_id"] = folly::to<std::string>(streamId);
  d["frame_type"] = toQlogString(FrameType::STREAM);
  return d;
}

folly::dynamic DatagramFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::DATAGRAM);
  d["length"] = len;
  return d;
}

folly::dynamic CryptoFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::CRYPTO_FRAME);
  d["offset"] = offset;
  d["len"] = len;
  return d;
}

folly::dynamic StopSendingFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::STOP_SENDING);
  d["stream_id"] = streamId;
  d["error_code"] = errorCode;
  return d;
}

folly::dynamic PathChallengeFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::PATH_CHALLENGE);
  d["path_data"] = pathData;
  return d;
}

folly::dynamic PathResponseFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::PATH_RESPONSE);
  d["path_data"] = pathData;
  return d;
}

folly::dynamic NewConnectionIdFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::NEW_CONNECTION_ID);
  d["sequence"] = sequence;

  folly::dynamic dToken = folly::dynamic::array();
  for (const auto& a : token) {
    dToken.push_back(a);
  }

  d["token"] = dToken;
  return d;
}

folly::dynamic RetireConnectionIdFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::RETIRE_CONNECTION_ID);
  d["sequence"] = sequence;
  return d;
}

folly::dynamic ReadAckFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  folly::dynamic ackRangeDynamic = folly::dynamic::array();
  folly::dynamic recvdPacketsTimestampRangesDynamic = folly::dynamic::array();

  for (const auto& b : ackBlocks) {
    ackRangeDynamic.push_back(
        folly::dynamic::array(b.startPacket, b.endPacket));
  }
  d["acked_ranges"] = ackRangeDynamic;
  d["frame_type"] = toQlogString(frameType);
  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    if (maybeLatestRecvdPacketTime.has_value()) {
      d["latest_recvd_packet_time"] =
          maybeLatestRecvdPacketTime.value().count();
    }
    if (maybeLatestRecvdPacketNum.has_value()) {
      d["latest_recvd_packet_num"] = maybeLatestRecvdPacketNum.value();
    }
    for (auto it = recvdPacketsTimestampRanges.cbegin();
         it != recvdPacketsTimestampRanges.cend();
         ++it) {
      folly::dynamic currentRxTimestampRange = folly::dynamic::object();
      currentRxTimestampRange["gap"] = it->gap;
      currentRxTimestampRange["timestamp_delta_count"] =
          it->timestamp_delta_count;
      currentRxTimestampRange["deltas"] =
          folly::dynamic::array(it->deltas.begin(), it->deltas.end());

      recvdPacketsTimestampRangesDynamic.push_back(currentRxTimestampRange);
    }
    d["timestamp_ranges"] = recvdPacketsTimestampRangesDynamic;
  }
  d["ack_delay"] = ackDelay.count();
  return d;
}

folly::dynamic WriteAckFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  folly::dynamic ackRangeDynamic = folly::dynamic::array();
  folly::dynamic recvdPacketsTimestampRangesDynamic = folly::dynamic::array();

  for (auto it = ackBlocks.cbegin(); it != ackBlocks.cend(); ++it) {
    ackRangeDynamic.push_back(folly::dynamic::array(it->start, it->end));
  }
  d["acked_ranges"] = ackRangeDynamic;
  d["frame_type"] = toQlogString(frameType);
  if (frameType == FrameType::ACK_RECEIVE_TIMESTAMPS) {
    if (maybeLatestRecvdPacketTime.has_value()) {
      d["latest_recvd_packet_time"] =
          maybeLatestRecvdPacketTime.value().count();
    }
    if (maybeLatestRecvdPacketNum.has_value()) {
      d["latest_recvd_packet_num"] = maybeLatestRecvdPacketNum.value();
    }

    for (auto it = recvdPacketsTimestampRanges.cbegin();
         it != recvdPacketsTimestampRanges.cend();
         ++it) {
      folly::dynamic currentRxTimestampRange = folly::dynamic::object();
      currentRxTimestampRange["gap"] = it->gap;
      currentRxTimestampRange["timestamp_delta_count"] =
          it->timestamp_delta_count;

      currentRxTimestampRange["deltas"] =
          folly::dynamic::array(it->deltas.begin(), it->deltas.end());
      recvdPacketsTimestampRangesDynamic.push_back(currentRxTimestampRange);
    }
    d["timestamp_ranges"] = recvdPacketsTimestampRangesDynamic;
  }
  d["ack_delay"] = ackDelay.count();
  return d;
}

folly::dynamic ReadNewTokenFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::NEW_TOKEN);
  return d;
}

folly::dynamic HandshakeDoneFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toQlogString(FrameType::HANDSHAKE_DONE);
  return d;
}

folly::dynamic VersionNegotiationLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d = folly::dynamic::array();
  for (const auto& v : versions) {
    d.push_back(toString(v));
  }
  return d;
}

folly::dynamic QLogPacketEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "transport",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["header"] = folly::dynamic::object("packet_size", packetSize);

  // A Retry packet does not include a packet number.
  if (packetType != toString(LongHeader::Types::Retry)) {
    data["header"]["packet_number"] = packetNum;
    data["frames"] = folly::dynamic::array();

    for (const auto& frame : frames) {
      data["frames"].push_back(frame->toDynamic());
    }
  }
  data["packet_type"] = packetType;

  d.push_back(std::move(data));
  return d;
}

folly::dynamic QLogVersionNegotiationEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data

  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "transport",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["versions"] = versionLog->toDynamic();
  data["header"] = folly::dynamic::object("packet_size", packetSize);
  data["packet_type"] = packetType;

  d.push_back(std::move(data));
  return d;
}

folly::dynamic QLogRetryEvent::toDynamic() const {
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "transport",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["header"] = folly::dynamic::object("packet_size", packetSize);
  data["packet_type"] = packetType;
  data["token_size"] = tokenSize;

  d.push_back(std::move(data));
  return d;
}

QLogConnectionCloseEvent::QLogConnectionCloseEvent(
    std::string errorIn,
    std::string reasonIn,
    bool drainConnectionIn,
    bool sendCloseImmediatelyIn,
    std::chrono::microseconds refTimeIn)
    : error{std::move(errorIn)},
      reason{std::move(reasonIn)},
      drainConnection{drainConnectionIn},
      sendCloseImmediately{sendCloseImmediatelyIn} {
  eventType = QLogEventType::ConnectionClose;
  refTime = refTimeIn;
}

folly::dynamic QLogConnectionCloseEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "connectivity",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["error"] = error;
  data["reason"] = reason;
  data["drain_connection"] = drainConnection;
  data["send_close_immediately"] = sendCloseImmediately;

  d.push_back(std::move(data));
  return d;
}

QLogTransportSummaryEvent::QLogTransportSummaryEvent(
    uint64_t totalBytesSentIn,
    uint64_t totalBytesRecvdIn,
    uint64_t sumCurWriteOffsetIn,
    uint64_t sumMaxObservedOffsetIn,
    uint64_t sumCurStreamBufferLenIn,
    uint64_t totalBytesRetransmittedIn,
    uint64_t totalStreamBytesClonedIn,
    uint64_t totalBytesClonedIn,
    uint64_t totalCryptoDataWrittenIn,
    uint64_t totalCryptoDataRecvdIn,
    uint64_t currentWritableBytesIn,
    uint64_t currentConnFlowControlIn,
    uint64_t totalPacketsSpuriouslyMarkedLost,
    uint64_t finalPacketLossReorderingThreshold,
    uint64_t finalPacketLossTimeReorderingThreshDividend,
    bool usedZeroRttIn,
    QuicVersion quicVersionIn,
    uint64_t dsrPacketCountIn,
    std::chrono::microseconds refTimeIn)
    : totalBytesSent{totalBytesSentIn},
      totalBytesRecvd{totalBytesRecvdIn},
      sumCurWriteOffset{sumCurWriteOffsetIn},
      sumMaxObservedOffset{sumMaxObservedOffsetIn},
      sumCurStreamBufferLen{sumCurStreamBufferLenIn},
      totalBytesRetransmitted{totalBytesRetransmittedIn},
      totalStreamBytesCloned{totalStreamBytesClonedIn},
      totalBytesCloned{totalBytesClonedIn},
      totalCryptoDataWritten{totalCryptoDataWrittenIn},
      totalCryptoDataRecvd{totalCryptoDataRecvdIn},
      currentWritableBytes{currentWritableBytesIn},
      currentConnFlowControl{currentConnFlowControlIn},
      totalPacketsSpuriouslyMarkedLost{totalPacketsSpuriouslyMarkedLost},
      finalPacketLossReorderingThreshold{finalPacketLossReorderingThreshold},
      finalPacketLossTimeReorderingThreshDividend{
          finalPacketLossTimeReorderingThreshDividend},
      usedZeroRtt{usedZeroRttIn},
      quicVersion{quicVersionIn},
      dsrPacketCount{dsrPacketCountIn} {
  eventType = QLogEventType::TransportSummary;
  refTime = refTimeIn;
}

folly::dynamic QLogTransportSummaryEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "transport",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["total_bytes_sent"] = totalBytesSent;
  data["total_bytes_recvd"] = totalBytesRecvd;
  data["sum_cur_write_offset"] = sumCurWriteOffset;
  data["sum_max_observed_offset"] = sumMaxObservedOffset;
  data["sum_cur_stream_buffer_len"] = sumCurStreamBufferLen;
  data["total_bytes_retransmitted"] = totalBytesRetransmitted;
  data["total_stream_bytes_cloned"] = totalStreamBytesCloned;
  data["total_bytes_cloned"] = totalBytesCloned;
  data["total_crypto_data_written"] = totalCryptoDataWritten;
  data["total_crypto_data_recvd"] = totalCryptoDataRecvd;
  data["current_writable_bytes"] = currentWritableBytes;
  data["current_conn_flow_control"] = currentConnFlowControl;
  data["total_packets_spuriously_marked_lost"] =
      totalPacketsSpuriouslyMarkedLost;
  data["final_packet_loss_reordering_threshold"] =
      finalPacketLossReorderingThreshold;
  data["final_packet_loss_time_reordering_threshold_dividend"] =
      finalPacketLossTimeReorderingThreshDividend;
  data["used_zero_rtt"] = usedZeroRtt;
  data["quic_version"] =
      static_cast<std::underlying_type<decltype(quicVersion)>::type>(
          quicVersion);
  data["dsr_packet_count"] = dsrPacketCount;

  d.push_back(std::move(data));
  return d;
}

QLogCongestionMetricUpdateEvent::QLogCongestionMetricUpdateEvent(
    uint64_t bytesInFlightIn,
    uint64_t currentCwndIn,
    std::string congestionEventIn,
    std::string stateIn,
    std::string recoveryStateIn,
    std::chrono::microseconds refTimeIn)
    : bytesInFlight{bytesInFlightIn},
      currentCwnd{currentCwndIn},
      congestionEvent{std::move(congestionEventIn)},
      state{std::move(stateIn)},
      recoveryState{std::move(recoveryStateIn)} {
  eventType = QLogEventType::CongestionMetricUpdate;
  refTime = refTimeIn;
}

folly::dynamic QLogCongestionMetricUpdateEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "metric_update",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["bytes_in_flight"] = bytesInFlight;
  data["current_cwnd"] = currentCwnd;
  data["congestion_event"] = congestionEvent;
  data["state"] = state;
  data["recovery_state"] = recoveryState;

  d.push_back(std::move(data));
  return d;
}

QLogAppLimitedUpdateEvent::QLogAppLimitedUpdateEvent(
    bool limitedIn,
    std::chrono::microseconds refTimeIn)
    : limited(limitedIn) {
  eventType = QLogEventType::AppLimitedUpdate;
  refTime = refTimeIn;
}

folly::dynamic QLogAppLimitedUpdateEvent::toDynamic() const {
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "APP_LIMITED_UPDATE",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();
  data["app_limited"] = limited ? kAppLimited : kAppUnlimited;
  d.push_back(std::move(data));
  return d;
}

QLogBandwidthEstUpdateEvent::QLogBandwidthEstUpdateEvent(
    uint64_t bytesIn,
    std::chrono::microseconds intervalIn,
    std::chrono::microseconds refTimeIn)
    : bytes(bytesIn), interval(intervalIn) {
  refTime = refTimeIn;
  eventType = QLogEventType::BandwidthEstUpdate;
}

folly::dynamic QLogBandwidthEstUpdateEvent::toDynamic() const {
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "BANDIWDTH_EST_UPDATE",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();
  data["bandwidth_bytes"] = bytes;
  data["bandwidth_interval"] = interval.count();
  d.push_back(std::move(data));
  return d;
}

QLogPacingMetricUpdateEvent::QLogPacingMetricUpdateEvent(
    uint64_t pacingBurstSizeIn,
    std::chrono::microseconds pacingIntervalIn,
    std::chrono::microseconds refTimeIn)
    : pacingBurstSize{pacingBurstSizeIn}, pacingInterval{pacingIntervalIn} {
  eventType = QLogEventType::PacingMetricUpdate;
  refTime = refTimeIn;
}

folly::dynamic QLogPacingMetricUpdateEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "metric_update",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["pacing_burst_size"] = pacingBurstSize;
  data["pacing_interval"] = pacingInterval.count();

  d.push_back(std::move(data));
  return d;
}

QLogPacingObservationEvent::QLogPacingObservationEvent(
    std::string actualIn,
    std::string expectIn,
    std::string conclusionIn,
    std::chrono::microseconds refTimeIn)
    : actual(std::move(actualIn)),
      expect(std::move(expectIn)),
      conclusion(std::move(conclusionIn)) {
  eventType = QLogEventType::PacingObservation;
  refTime = refTimeIn;
}

// TODO: Sad. I wanted moved all the string into the dynamic but this function
// is const. I think we should make all the toDynamic rvalue qualified since
// users are not supposed to use them after toDynamic() is called.
folly::dynamic QLogPacingObservationEvent::toDynamic() const {
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "metric_update",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["actual_pacing_rate"] = actual;
  data["expect_pacing_rate"] = expect;
  data["conclusion"] = conclusion;

  d.push_back(std::move(data));
  return d;
}

QLogAppIdleUpdateEvent::QLogAppIdleUpdateEvent(
    std::string idleEventIn,
    bool idleIn,
    std::chrono::microseconds refTimeIn)
    : idleEvent{std::move(idleEventIn)}, idle{idleIn} {
  eventType = QLogEventType::AppIdleUpdate;
  refTime = refTimeIn;
}

folly::dynamic QLogAppIdleUpdateEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "idle_update",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["idle_event"] = idleEvent;
  data["idle"] = idle;

  d.push_back(std::move(data));
  return d;
}

QLogPacketDropEvent::QLogPacketDropEvent(
    size_t packetSizeIn,
    std::string dropReasonIn,
    std::chrono::microseconds refTimeIn)
    : packetSize{packetSizeIn}, dropReason{std::move(dropReasonIn)} {
  eventType = QLogEventType::PacketDrop;
  refTime = refTimeIn;
}

folly::dynamic QLogPacketDropEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()), "loss", toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["packet_size"] = packetSize;
  data["drop_reason"] = dropReason;

  d.push_back(std::move(data));
  return d;
} // namespace quic

QLogDatagramReceivedEvent::QLogDatagramReceivedEvent(
    uint64_t dataLen,
    std::chrono::microseconds refTimeIn)
    : dataLen{dataLen} {
  eventType = QLogEventType::DatagramReceived;
  refTime = refTimeIn;
}

folly::dynamic QLogDatagramReceivedEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "transport",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["data_len"] = dataLen;

  d.push_back(std::move(data));
  return d;
}

QLogLossAlarmEvent::QLogLossAlarmEvent(
    PacketNum largestSentIn,
    uint64_t alarmCountIn,
    uint64_t outstandingPacketsIn,
    std::string typeIn,
    std::chrono::microseconds refTimeIn)
    : largestSent{largestSentIn},
      alarmCount{alarmCountIn},
      outstandingPackets{outstandingPacketsIn},
      type{std::move(typeIn)} {
  eventType = QLogEventType::LossAlarm;
  refTime = refTimeIn;
}

folly::dynamic QLogLossAlarmEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()), "loss", toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["largest_sent"] = largestSent;
  data["alarm_count"] = alarmCount;
  data["outstanding_packets"] = outstandingPackets;
  data["type"] = type;

  d.push_back(std::move(data));
  return d;
}

QLogPacketsLostEvent::QLogPacketsLostEvent(
    PacketNum largestLostPacketNumIn,
    uint64_t lostBytesIn,
    uint64_t lostPacketsIn,
    std::chrono::microseconds refTimeIn)
    : largestLostPacketNum{largestLostPacketNumIn},
      lostBytes{lostBytesIn},
      lostPackets{lostPacketsIn} {
  eventType = QLogEventType::PacketsLost;
  refTime = refTimeIn;
}

folly::dynamic QLogPacketsLostEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()), "loss", toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["largest_lost_packet_num"] = largestLostPacketNum;
  data["lost_bytes"] = lostBytes;
  data["lost_packets"] = lostPackets;

  d.push_back(std::move(data));
  return d;
}

QLogTransportStateUpdateEvent::QLogTransportStateUpdateEvent(
    std::string updateIn,
    std::chrono::microseconds refTimeIn)
    : update{std::move(updateIn)} {
  eventType = QLogEventType::TransportStateUpdate;
  refTime = refTimeIn;
}

folly::dynamic QLogTransportStateUpdateEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "transport",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["update"] = update;

  d.push_back(std::move(data));
  return d;
}

QLogPacketBufferedEvent::QLogPacketBufferedEvent(
    ProtectionType protectionTypeIn,
    uint64_t packetSizeIn,
    std::chrono::microseconds refTimeIn)
    : protectionType{protectionTypeIn}, packetSize{packetSizeIn} {
  eventType = QLogEventType::PacketBuffered;
  refTime = refTimeIn;
}

folly::dynamic QLogPacketBufferedEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "transport",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["protection_type"] = toString(protectionType);
  data["packet_size"] = packetSize;

  d.push_back(std::move(data));
  return d;
}

QLogPacketAckEvent::QLogPacketAckEvent(
    PacketNumberSpace packetNumSpaceIn,
    PacketNum packetNumIn,
    std::chrono::microseconds refTimeIn)
    : packetNumSpace{packetNumSpaceIn}, packetNum{packetNumIn} {
  eventType = QLogEventType::PacketAck;
  refTime = refTimeIn;
}

folly::dynamic QLogPacketAckEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "transport",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["packet_num_space"] = folly::to<std::string>(packetNumSpace);
  data["packet_num"] = packetNum;

  d.push_back(std::move(data));
  return d;
}

QLogMetricUpdateEvent::QLogMetricUpdateEvent(
    std::chrono::microseconds latestRttIn,
    std::chrono::microseconds mrttIn,
    std::chrono::microseconds srttIn,
    std::chrono::microseconds ackDelayIn,
    std::chrono::microseconds refTimeIn)
    : latestRtt{latestRttIn}, mrtt{mrttIn}, srtt{srttIn}, ackDelay{ackDelayIn} {
  eventType = QLogEventType::MetricUpdate;
  refTime = refTimeIn;
}

folly::dynamic QLogMetricUpdateEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()), "recovery", toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["latest_rtt"] = latestRtt.count();
  data["min_rtt"] = mrtt.count();
  data["smoothed_rtt"] = srtt.count();
  data["ack_delay"] = ackDelay.count();

  d.push_back(std::move(data));
  return d;
}

QLogStreamStateUpdateEvent::QLogStreamStateUpdateEvent(
    StreamId idIn,
    std::string updateIn,
    folly::Optional<std::chrono::milliseconds> timeSinceStreamCreationIn,
    VantagePoint vantagePoint,
    std::chrono::microseconds refTimeIn)
    : id{idIn},
      update{std::move(updateIn)},
      timeSinceStreamCreation(std::move(timeSinceStreamCreationIn)),
      vantagePoint_(vantagePoint) {
  eventType = QLogEventType::StreamStateUpdate;
  refTime = refTimeIn;
}

folly::dynamic QLogStreamStateUpdateEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()), "HTTP3", toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["id"] = id;
  data["update"] = update;
  if (timeSinceStreamCreation) {
    if (update == kOnEOM && vantagePoint_ == VantagePoint::Client) {
      data["ttlb"] = timeSinceStreamCreation->count();
    } else if (update == kOnHeaders && vantagePoint_ == VantagePoint::Client) {
      data["ttfb"] = timeSinceStreamCreation->count();
    } else {
      data["ms_since_creation"] = timeSinceStreamCreation->count();
    }
  }

  d.push_back(std::move(data));
  return d;
}

QLogConnectionMigrationEvent::QLogConnectionMigrationEvent(
    bool intentionalMigration,
    VantagePoint vantagePoint,
    std::chrono::microseconds refTimeIn)
    : intentionalMigration_{intentionalMigration}, vantagePoint_(vantagePoint) {
  eventType = QLogEventType::ConnectionMigration;
  refTime = refTimeIn;
}

folly::dynamic QLogConnectionMigrationEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "transport",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["intentional"] = intentionalMigration_;
  if (vantagePoint_ == VantagePoint::Client) {
    data["type"] = "initiating";
  } else {
    data["type"] = "accepting";
  }
  d.push_back(std::move(data));
  return d;
}

QLogPathValidationEvent::QLogPathValidationEvent(
    bool success,
    VantagePoint vantagePoint,
    std::chrono::microseconds refTimeIn)
    : success_{success}, vantagePoint_(vantagePoint) {
  eventType = QLogEventType::PathValidation;
  refTime = refTimeIn;
}

folly::dynamic QLogPathValidationEvent::toDynamic() const {
  // creating a folly::dynamic array to hold the information corresponding to
  // the event fields relative_time, category, event_type, trigger, data
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()),
      "transport",
      toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["success"] = success_;
  if (vantagePoint_ == VantagePoint::Client) {
    data["vantagePoint"] = "client";
  } else {
    data["vantagePoint"] = "server";
  }
  d.push_back(std::move(data));
  return d;
}

QLogPriorityUpdateEvent::QLogPriorityUpdateEvent(
    StreamId streamId,
    uint8_t urgency,
    bool incremental,
    std::chrono::microseconds refTimeIn)
    : streamId_(streamId), urgency_(urgency), incremental_(incremental) {
  eventType = QLogEventType::PriorityUpdate;
  refTime = refTimeIn;
}

folly::dynamic QLogPriorityUpdateEvent::toDynamic() const {
  folly::dynamic d = folly::dynamic::array(
      folly::to<std::string>(refTime.count()), "HTTP3", toString(eventType));
  folly::dynamic data = folly::dynamic::object();

  data["id"] = streamId_;
  data["urgency"] = urgency_;
  data["incremental"] = incremental_;
  d.push_back(std::move(data));
  return d;
}

folly::StringPiece toString(QLogEventType type) {
  switch (type) {
    case QLogEventType::PacketSent:
      return "packet_sent";
    case QLogEventType::PacketReceived:
      return "packet_received";
    case QLogEventType::ConnectionClose:
      return "connection_close";
    case QLogEventType::TransportSummary:
      return "transport_summary";
    case QLogEventType::CongestionMetricUpdate:
      return "congestion_metric_update";
    case QLogEventType::PacingMetricUpdate:
      return "pacing_metric_update";
    case QLogEventType::AppIdleUpdate:
      return "app_idle_update";
    case QLogEventType::PacketDrop:
      return "packet_drop";
    case QLogEventType::DatagramReceived:
      return "datagram_received";
    case QLogEventType::LossAlarm:
      return "loss_alarm";
    case QLogEventType::PacketsLost:
      return "packets_lost";
    case QLogEventType::TransportStateUpdate:
      return "transport_state_update";
    case QLogEventType::PacketBuffered:
      return "packet_buffered";
    case QLogEventType::PacketAck:
      return "packet_ack";
    case QLogEventType::MetricUpdate:
      return "metric_update";
    case QLogEventType::StreamStateUpdate:
      return "stream_state_update";
    case QLogEventType::PacingObservation:
      return "pacing_observation";
    case QLogEventType::AppLimitedUpdate:
      return "app_limited_update";
    case QLogEventType::BandwidthEstUpdate:
      return "bandwidth_est_update";
    case QLogEventType::ConnectionMigration:
      return "connection_migration";
    case QLogEventType::PathValidation:
      return "path_validation";
    case QLogEventType::PriorityUpdate:
      return "priority";
  }
  folly::assume_unreachable();
}
} // namespace quic
