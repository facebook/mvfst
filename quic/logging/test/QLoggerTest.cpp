/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/logging/QLogger.h>

#include <folly/FileUtil.h>
#include <folly/Random.h>
#include <folly/json.h>
#include <folly/portability/Filesystem.h>
#include <gtest/gtest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/Bbr.h>
#include <quic/logging/FileQLogger.h>
#include <chrono>

using namespace testing;

namespace quic::test {
class QLoggerTest : public Test {
 public:
  StreamId streamId{10};
  PacketNum packetNumSent{10};
  uint64_t offset{0};
  uint64_t len{0};
  bool fin{true};
  bool isPacketRecvd{false};
};

TEST_F(QLoggerTest, TestRegularWritePacket) {
  std::string fakeProtocolType = "some-fake-protocol-type";
  RegularQuicWritePacket regularWritePacket =
      createRegularQuicWritePacket(streamId, offset, len, fin);

  FileQLogger q(VantagePoint::Client, fakeProtocolType);
  EXPECT_EQ(q.vantagePoint, VantagePoint::Client);
  EXPECT_EQ(q.protocolType, fakeProtocolType);
  q.addPacket(regularWritePacket, 10);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketEvent*>(p.get());
  auto gotObject = *static_cast<StreamFrameLog*>(gotEvent->frames[0].get());

  EXPECT_EQ(gotObject.streamId, streamId);
  EXPECT_EQ(gotObject.offset, offset);
  EXPECT_EQ(gotObject.fin, fin);
  EXPECT_EQ(gotEvent->eventType, QLogEventType::PacketSent);
}

TEST_F(QLoggerTest, TestRegularPacket) {
  auto headerIn =
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(1), 1);
  RegularQuicPacket regularQuicPacket(std::move(headerIn));
  ReadStreamFrame frame(streamId, offset, fin);

  regularQuicPacket.frames.emplace_back(std::move(frame));

  FileQLogger q(VantagePoint::Client);
  q.addPacket(regularQuicPacket, 10);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketEvent*>(p.get());
  auto gotObject = *static_cast<StreamFrameLog*>(gotEvent->frames[0].get());

  EXPECT_EQ(gotObject.streamId, streamId);
  EXPECT_EQ(gotObject.offset, offset);
  EXPECT_EQ(gotObject.fin, fin);
  EXPECT_EQ(gotEvent->eventType, QLogEventType::PacketReceived);
}

TEST_F(QLoggerTest, TestVersionNegotiationPacket) {
  bool isPacketRecvd = false;
  FileQLogger q(VantagePoint::Client);
  auto packet = createVersionNegotiationPacket();
  q.addPacket(packet, 10, isPacketRecvd);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogVersionNegotiationEvent*>(p.get());
  auto gotObject = *gotEvent->versionLog.get();

  EXPECT_EQ(gotObject.versions, packet.versions);
}

TEST_F(QLoggerTest, ConnectionCloseEvent) {
  FileQLogger q(VantagePoint::Client);
  auto error = toString(LocalErrorCode::CONNECTION_RESET);
  q.addConnectionClose(error.str(), "Connection close", true, false);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogConnectionCloseEvent*>(p.get());
  EXPECT_EQ(gotEvent->error, error);
  EXPECT_EQ(gotEvent->drainConnection, true);
  EXPECT_EQ(gotEvent->sendCloseImmediately, false);
}

TEST_F(QLoggerTest, TransportSummaryEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addTransportSummary(
      {8,
       9,
       5,
       3,
       2,
       554,
       100,
       32,
       134,
       238,
       22,
       44,
       45,
       46,
       47,
       false,
       QuicVersion::MVFST,
       37});

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogTransportSummaryEvent*>(p.get());

  EXPECT_EQ(gotEvent->totalBytesSent, 8);
  EXPECT_EQ(gotEvent->totalBytesRecvd, 9);
  EXPECT_EQ(gotEvent->sumCurWriteOffset, 5);
  EXPECT_EQ(gotEvent->sumMaxObservedOffset, 3);
  EXPECT_EQ(gotEvent->sumCurStreamBufferLen, 2);
  EXPECT_EQ(gotEvent->totalBytesRetransmitted, 554);
  EXPECT_EQ(gotEvent->totalStreamBytesCloned, 100);
  EXPECT_EQ(gotEvent->totalBytesCloned, 32);
  EXPECT_EQ(gotEvent->totalCryptoDataWritten, 134);
  EXPECT_EQ(gotEvent->totalCryptoDataRecvd, 238);
  EXPECT_EQ(gotEvent->currentWritableBytes, 22);
  EXPECT_EQ(gotEvent->currentConnFlowControl, 44);
  EXPECT_EQ(gotEvent->totalPacketsSpuriouslyMarkedLost, 45);
  EXPECT_EQ(gotEvent->finalPacketLossReorderingThreshold, 46);
  EXPECT_EQ(gotEvent->finalPacketLossTimeReorderingThreshDividend, 47);
  EXPECT_EQ(gotEvent->usedZeroRtt, false);
  EXPECT_EQ(gotEvent->dsrPacketCount, 37);
}

TEST_F(QLoggerTest, CongestionMetricUpdateEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addCongestionMetricUpdate(
      20,
      30,
      kPersistentCongestion,
      cubicStateToString(CubicStates::Steady).str(),
      bbrRecoveryStateToString(
          BbrCongestionController::RecoveryState::NOT_RECOVERY));

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogCongestionMetricUpdateEvent*>(p.get());

  EXPECT_EQ(gotEvent->bytesInFlight, 20);
  EXPECT_EQ(gotEvent->currentCwnd, 30);
  EXPECT_EQ(gotEvent->congestionEvent, kPersistentCongestion);
  EXPECT_EQ(gotEvent->state, cubicStateToString(CubicStates::Steady).str());
  EXPECT_EQ(
      gotEvent->recoveryState,
      bbrRecoveryStateToString(
          BbrCongestionController::RecoveryState::NOT_RECOVERY));
}

TEST_F(QLoggerTest, PacingMetricUpdateEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addPacingMetricUpdate(10, 30us);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacingMetricUpdateEvent*>(p.get());

  EXPECT_EQ(gotEvent->pacingBurstSize, 10);
  EXPECT_EQ(gotEvent->pacingInterval, 30us);
}

TEST_F(QLoggerTest, AppIdleUpdateEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addAppIdleUpdate(kAppIdle, false);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogAppIdleUpdateEvent*>(p.get());

  EXPECT_EQ(gotEvent->idleEvent, kAppIdle);
  EXPECT_FALSE(gotEvent->idle);
}

TEST_F(QLoggerTest, PacketDropEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addPacketDrop(5, kCipherUnavailable);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketDropEvent*>(p.get());

  EXPECT_EQ(gotEvent->packetSize, 5);
  EXPECT_EQ(gotEvent->dropReason, kCipherUnavailable);
}

TEST_F(QLoggerTest, DatagramReceivedEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addDatagramReceived(100);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogDatagramReceivedEvent*>(p.get());

  EXPECT_EQ(gotEvent->dataLen, 100);
}

TEST_F(QLoggerTest, LossAlarmEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addLossAlarm(PacketNum{1}, 3983, 893, kPtoAlarm);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogLossAlarmEvent*>(p.get());

  EXPECT_EQ(gotEvent->largestSent, 1);
  EXPECT_EQ(gotEvent->alarmCount, 3983);
  EXPECT_EQ(gotEvent->outstandingPackets, 893);
  EXPECT_EQ(gotEvent->type, kPtoAlarm);
}

TEST_F(QLoggerTest, PacketsLostEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addPacketsLost(PacketNum{42}, 332, 89);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketsLostEvent*>(p.get());

  EXPECT_EQ(gotEvent->largestLostPacketNum, 42);
  EXPECT_EQ(gotEvent->lostBytes, 332);
  EXPECT_EQ(gotEvent->lostPackets, 89);
}

TEST_F(QLoggerTest, TransportStateUpdateEvent) {
  FileQLogger q(VantagePoint::Client);
  std::string update = "start";
  q.addTransportStateUpdate(update);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogTransportStateUpdateEvent*>(p.get());

  EXPECT_EQ(gotEvent->update, update);
}

TEST_F(QLoggerTest, PacketBufferedEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addPacketBuffered(ProtectionType::Handshake, 100);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketBufferedEvent*>(p.get());

  EXPECT_EQ(gotEvent->protectionType, ProtectionType::Handshake);
  EXPECT_EQ(gotEvent->packetSize, 100);
}

TEST_F(QLoggerTest, MetricUpdateEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addMetricUpdate(10us, 11us, 12us, 13us);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogMetricUpdateEvent*>(p.get());

  EXPECT_EQ(gotEvent->latestRtt, 10us);
  EXPECT_EQ(gotEvent->mrtt, 11us);
  EXPECT_EQ(gotEvent->srtt, 12us);
  EXPECT_EQ(gotEvent->ackDelay, 13us);
}

TEST_F(QLoggerTest, StreamStateUpdateEvent) {
  FileQLogger q(VantagePoint::Client);
  q.addStreamStateUpdate(streamId, kAbort, 20ms);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogStreamStateUpdateEvent*>(p.get());

  EXPECT_EQ(gotEvent->id, streamId);
  EXPECT_EQ(gotEvent->update, kAbort);
  EXPECT_EQ(20ms, gotEvent->timeSinceStreamCreation);
}

TEST_F(QLoggerTest, PacketPaddingFrameEvent) {
  FileQLogger q(VantagePoint::Client);
  auto packet = createPacketWithPaddingFrames();
  q.addPacket(packet, 100);

  EXPECT_EQ(q.logs.size(), 1);
  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketEvent*>(p.get());
  auto gotObject = *static_cast<PaddingFrameLog*>(gotEvent->frames[0].get());

  EXPECT_EQ(gotObject.numFrames, 20);
}

TEST_F(QLoggerTest, QLoggerFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"({
   "description": "Converted from file",
   "qlog_version": "draft-00",
   "summary": {
     "max_duration": 0,
     "total_event_count": 1,
     "trace_count": 1
   },
   "title": "mvfst qlog",
   "traces": [
     {
       "common_fields": {
         "dcid": "",
         "protocol_type": "QUIC_HTTP3",
         "reference_time": "0",
         "scid": ""
       },
       "configuration": {
         "time_offset": 0,
         "time_units": "us"
       },
       "description": "Generated qlog from connection",
       "event_fields": [
         "relative_time",
         "category",
         "event",
         "data"
       ],
       "events": [
         [
           "31",
           "transport",
           "packet_received",
           {
             "frames": [
               {
                 "fin": true,
                 "frame_type": "stream",
                 "stream_id": "10",
                 "length": 0,
                 "offset": 0
               }
             ],
             "header": {
               "packet_number": 1,
               "packet_size": 10
             },
             "packet_type": "1RTT"
           }
         ]
       ],
       "title": "mvfst qlog from single connection",
       "vantage_point": {
         "name": "server",
         "type": "server"
       }
     }
   ]
 })");

  auto headerIn =
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(1), 1);
  RegularQuicPacket regularQuicPacket(std::move(headerIn));
  ReadStreamFrame frame(streamId, offset, fin);

  regularQuicPacket.frames.emplace_back(std::move(frame));

  FileQLogger q(VantagePoint::Server);
  q.addPacket(regularQuicPacket, 10);

  q.logs[0]->refTime = 31us;
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "31"; // hardcode reference time
  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, RegularPacketFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
       [
         "0",
         "transport",
         "packet_received",
         {
           "frames": [
             {
               "fin": true,
               "frame_type": "stream",
               "stream_id": "10",
               "length": 0,
               "offset": 0
             }
           ],
           "header": {
             "packet_number": 1,
             "packet_size": 10
           },
           "packet_type": "1RTT"
         }
       ]
     ])");

  auto headerIn =
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(1), 1);
  RegularQuicPacket regularQuicPacket(std::move(headerIn));
  ReadStreamFrame frame(streamId, offset, fin);

  regularQuicPacket.frames.emplace_back(std::move(frame));

  FileQLogger q(VantagePoint::Client);
  q.addPacket(regularQuicPacket, 10);

  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, RegularWritePacketFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
           [
             "0",
             "transport",
             "packet_sent",
             {
               "frames": [
                 {
                   "fin": true,
                   "frame_type": "stream",
                   "stream_id": "10",
                   "length": 0,
                   "offset": 0
                 }
               ],
               "header": {
                 "packet_number": 10,
                 "packet_size": 10
               },
               "packet_type": "initial"
             }
           ]
         ])");

  RegularQuicWritePacket packet =
      createRegularQuicWritePacket(streamId, offset, len, fin);

  FileQLogger q(VantagePoint::Client);
  q.dcid = getTestConnectionId(0);
  q.scid = getTestConnectionId(1);
  q.addPacket(packet, 10);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, RegularPacketAckFrameFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
         [
           "0",
           "transport",
           "packet_sent",
           {
             "frames": [
               {
                 "ack_delay": 111,
                 "acked_ranges": [
                  [
                    900,
                    1000
                  ],
                  [
                    500,
                    700
                  ]
                 ],
                 "frame_type": "ack"
               }
             ],
             "header": {
               "packet_number": 100,
               "packet_size": 1001
             },
             "packet_type": "initial"
           }
         ]
       ])");

  RegularQuicWritePacket packet = createPacketWithAckFrames();
  FileQLogger q(VantagePoint::Client);
  q.addPacket(packet, 1001);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, VersionPacketFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
           [
             "0",
             "transport",
             "packet_sent",
             {
               "header": {
                 "packet_size": 10
               },
               "packet_type": "version_negotiation",
                "versions": [
                  "VERSION_NEGOTIATION",
                  "MVFST"
                ]
             }
         ]
   ])");

  auto packet = createVersionNegotiationPacket();
  FileQLogger q(VantagePoint::Client);
  q.dcid = getTestConnectionId(0);
  q.scid = getTestConnectionId(1);
  q.addPacket(packet, 10, isPacketRecvd);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, AddingMultiplePacketEvents) {
  auto buf = folly::IOBuf::copyBuffer("hello");
  folly::dynamic expected = folly::parseJson(
      R"({
   "description": "Converted from file",
   "qlog_version": "draft-00",
   "summary": {
     "max_duration": "300",
     "total_event_count": 3,
     "trace_count": 1
   },
   "title": "mvfst qlog",
   "traces": [
     {
       "common_fields": {
         "dcid": "",
         "protocol_type": "QUIC_HTTP3",
         "reference_time": "0",
         "scid": ""
       },
       "configuration": {
         "time_offset": 0,
         "time_units": "us"
       },
       "description": "Generated qlog from connection",
       "event_fields": [
         "relative_time",
         "category",
         "event",
         "data"
       ],
       "events": [
         [
           "0",
           "transport",
           "packet_sent",
           {
             "header": {
               "packet_size": 10
             },
             "packet_type": "version_negotiation",
             "versions": [
               "VERSION_NEGOTIATION",
               "MVFST"
             ]
           }
         ],
         [
           "1",
           "transport",
           "packet_sent",
           {
             "frames": [
               {
                 "ack_delay": 111,
                 "acked_ranges": [
                   [
                     900,
                     1000
                   ],
                   [
                     500,
                     700
                   ]
                 ],
                 "frame_type": "ack"
               }
             ],
             "header": {
               "packet_number": 100,
               "packet_size": 100
             },
             "packet_type": "initial"
           }
         ],
         [
           "2",
           "transport",
           "packet_sent",
           {
             "frames": [
               {
                 "fin": true,
                 "frame_type": "stream",
                 "stream_id": "10",
                 "length": 5,
                 "offset": 0
               }
             ],
             "header": {
               "packet_number": 1,
               "packet_size": 10
             },
             "packet_type": "1RTT"
           }
         ]
       ],
       "title": "mvfst qlog from single connection",
       "vantage_point": {
         "name": "server",
         "type": "server"
       }
     }
   ]
 })");

  FileQLogger q(VantagePoint::Server);
  auto versionPacket = createVersionNegotiationPacket();
  RegularQuicWritePacket regPacket = createPacketWithAckFrames();
  auto packet = createStreamPacket(
      getTestConnectionId(0),
      getTestConnectionId(1),
      1,
      streamId,
      *buf,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none /* longHeaderOverride */,
      fin,
      folly::none /* shortHeaderOverride */,
      offset);

  auto regularQuicPacket = packet.packet;

  q.addPacket(versionPacket, 10, isPacketRecvd);
  q.addPacket(regPacket, 100);
  q.addPacket(regularQuicPacket, 10);

  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["summary"]["max_duration"] = "300"; // hardcode reference time

  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  gotDynamic["traces"][0]["events"][1][0] = "1"; // hardcode reference time
  gotDynamic["traces"][0]["events"][2][0] = "2"; // hardcode reference time

  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, AddingMultipleFrames) {
  folly::dynamic expected = folly::parseJson(
      R"([
           [
             "0",
             "transport",
             "packet_sent",
             {
               "frames": [
                 {
                   "ack_delay": 111,
                   "acked_ranges": [
                     [
                       300,
                       400
                     ],
                     [
                       100,
                       200
                     ]
                   ],
                   "frame_type": "ack"
                 },
                 {
                   "fin": true,
                   "frame_type": "stream",
                   "stream_id": "10",
                   "length": 0,
                   "offset": 0
                 }
               ],
               "header": {
                 "packet_number": 100,
                 "packet_size": 10
               },
               "packet_type": "initial"
             }
           ]
  ])");

  FileQLogger q(VantagePoint::Client);
  RegularQuicWritePacket packet =
      createNewPacket(100, PacketNumberSpace::Initial);

  WriteAckFrame ackFrame;
  ackFrame.ackDelay = 111us;
  ackFrame.ackBlocks.emplace_back(300, 400);
  ackFrame.ackBlocks.emplace_back(100, 200);
  WriteStreamFrame streamFrame(streamId, offset, len, fin);

  packet.frames.emplace_back(std::move(ackFrame));
  packet.frames.emplace_back(std::move(streamFrame));

  q.addPacket(packet, 10);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, ConnectionCloseFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([[
           "0",
           "connectivity",
           "connection_close",
           {
             "drain_connection": true,
             "error": "Connection reset",
             "reason": "Connection changed",
             "send_close_immediately": false
           }
         ]])");

  FileQLogger q(VantagePoint::Client);
  auto error = toString(LocalErrorCode::CONNECTION_RESET);
  q.addConnectionClose(error.str(), "Connection changed", true, false);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, TransportSummaryFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
   [
     "0",
     "transport",
     "transport_summary",
     {
       "total_bytes_sent": 1,
       "total_bytes_recvd": 2,
       "sum_cur_write_offset": 3,
       "sum_max_observed_offset": 4,
       "sum_cur_stream_buffer_len": 5,
       "total_bytes_retransmitted": 6,
       "total_stream_bytes_cloned": 7,
       "total_bytes_cloned": 8,
       "total_crypto_data_written": 9,
       "total_crypto_data_recvd": 10,
       "current_writable_bytes": 11,
       "current_conn_flow_control": 12,
       "total_packets_spuriously_marked_lost": 13,
       "final_packet_loss_reordering_threshold": 14,
       "final_packet_loss_time_reordering_threshold_dividend": 15,
       "used_zero_rtt": true,
       "quic_version": 4207849474,
       "dsr_packet_count": 37
     }
   ]
 ])");

  FileQLogger q(VantagePoint::Client);
  q.addTransportSummary(
      {1,
       2,
       3,
       4,
       5,
       6,
       7,
       8,
       9,
       10,
       11,
       12,
       13,
       14,
       15,
       true,
       QuicVersion::MVFST,
       37});
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, CongestionMetricUpdateFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
      [
        "0",
        "metric_update",
        "congestion_metric_update",
        {
          "bytes_in_flight": 20,
          "congestion_event": "persistent congestion",
          "current_cwnd": 30,
          "recovery_state": "",
          "state": "Steady"
        }
      ]
 ])");

  FileQLogger q(VantagePoint::Client);
  q.addCongestionMetricUpdate(
      20,
      30,
      kPersistentCongestion,
      cubicStateToString(CubicStates::Steady).str());
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, PacingMetricUpdateFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
      [
        "0",
        "metric_update",
        "pacing_metric_update",
        {
         "pacing_burst_size": 20,
         "pacing_interval": 30
        }
      ]
 ])");

  FileQLogger q(VantagePoint::Client);
  q.addPacingMetricUpdate(20, 30us);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, AppIdleFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
      [
        "0",
        "idle_update",
        "app_idle_update",
        {
         "idle_event": "app idle",
         "idle": true
        }
      ]
 ])");

  FileQLogger q(VantagePoint::Client);
  q.addAppIdleUpdate(kAppIdle, true);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, PacketDropFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
      [
        "0",
        "loss",
        "packet_drop",
        {
         "drop_reason": "max buffered",
         "packet_size": 100
        }
      ]
 ])");

  FileQLogger q(VantagePoint::Client);
  q.addPacketDrop(100, kMaxBuffered);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, DatagramReceivedFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
      [
      "0",
       "transport",
       "datagram_received",
       {
         "data_len": 8
       }
      ]
 ])");

  FileQLogger q(VantagePoint::Client);
  q.addDatagramReceived(8);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, LossAlarmFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
      [
      "0",
       "loss",
       "loss_alarm",
       {
         "largest_sent": 100,
         "alarm_count": 14,
         "outstanding_packets": 38,
         "type": "handshake alarm"
       }
      ]
 ])");

  FileQLogger q(VantagePoint::Client);
  q.addLossAlarm(PacketNum{100}, 14, 38, kHandshakeAlarm);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, PacketsLostFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
      [
      "0",
       "loss",
       "packets_lost",
       {
         "largest_lost_packet_num": 10,
         "lost_bytes": 9,
         "lost_packets": 8
       }
      ]
 ])");

  FileQLogger q(VantagePoint::Client);
  q.addPacketsLost(PacketNum{10}, 9, 8);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, TransportStateUpdateFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
    [
    "0",
     "transport",
     "transport_state_update",
     {
       "update": "transport ready"
     }
    ]
])");

  FileQLogger q(VantagePoint::Client);
  q.addTransportStateUpdate("transport ready");
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, PacketBufferedFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
    [
    "0",
     "transport",
     "packet_buffered",
     {
       "protection_type": "Handshake",
       "packet_size": 100
     }
    ]
])");

  FileQLogger q(VantagePoint::Client);
  q.addPacketBuffered(ProtectionType::Handshake, 100);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, MetricUpdateFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
    [
      "0",
      "recovery",
      "metric_update",
      {
        "ack_delay": 13,
        "latest_rtt": 10,
        "min_rtt": 11,
        "smoothed_rtt": 12
      }
    ]
])");

  FileQLogger q(VantagePoint::Client);
  q.addMetricUpdate(10us, 11us, 12us, 13us);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, StreamStateUpdateFollyDynamicTTFB) {
  folly::dynamic expected = folly::parseJson(
      R"([
    [
      "0",
      "HTTP3",
      "stream_state_update",
      {
        "id": 10,
        "ttfb": 20,
        "update": "on headers"
      }
    ]
])");

  FileQLogger q(VantagePoint::Client);
  q.addStreamStateUpdate(streamId, kOnHeaders, 20ms);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, StreamStateUpdateFollyDynamicTTLB) {
  folly::dynamic expected = folly::parseJson(
      R"([
    [
      "0",
      "HTTP3",
      "stream_state_update",
      {
        "id": 10,
        "ttlb": 20,
        "update": "on eom"
      }
    ]
])");

  FileQLogger q(VantagePoint::Client);
  q.addStreamStateUpdate(streamId, kOnEOM, 20ms);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(
    QLoggerTest,
    StreamStateUpdateFollyDynamicMissingTimeSinceCreationField) {
  folly::dynamic expected = folly::parseJson(
      R"([
    [
      "0",
      "HTTP3",
      "stream_state_update",
      {
        "id": 10,
        "update": "on eom"
      }
    ]
])");

  FileQLogger q(VantagePoint::Client);
  q.addStreamStateUpdate(streamId, kOnEOM, folly::none);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, StreamStateUpdateFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
    [
      "0",
      "HTTP3",
      "stream_state_update",
      {
        "id": 10,
        "ms_since_creation": 20,
        "update": "abort"
      }
    ]
])");

  FileQLogger q(VantagePoint::Client);
  q.addStreamStateUpdate(streamId, kAbort, 20ms);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, PaddingFramesFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([
   [
     "0",
     "transport",
     "packet_sent",
     {
       "frames": [
         {
           "frame_type": "padding",
           "num_frames": 20
         }
       ],
       "header": {
         "packet_number": 100,
         "packet_size": 100
       },
       "packet_type": "initial"
     }
   ]
 ])");

  FileQLogger q(VantagePoint::Client);
  auto packet = createPacketWithPaddingFrames();
  q.addPacket(packet, 100);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, ConnectionMigration) {
  folly::dynamic expected = folly::parseJson(
      R"([
    [
      "0",
      "transport",
      "connection_migration",
      {
        "intentional": true,
        "type": "initiating"
      }
    ]
])");

  FileQLogger q(VantagePoint::Client);
  q.addConnectionMigrationUpdate(true);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, PathValidation) {
  folly::dynamic expected = folly::parseJson(
      R"([
    [
      "0",
      "transport",
      "path_validation",
      {
        "success": false,
        "vantagePoint": "server"
      }
    ]
])");

  FileQLogger q(VantagePoint::Server);
  q.addPathValidationEvent(false);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

TEST_F(QLoggerTest, PrettyStream) {
  folly::dynamic expected = folly::parseJson(
      R"({
   "description": "Converted from file",
   "qlog_version": "draft-00",
   "title": "mvfst qlog",
   "traces": [
     {
       "common_fields": {
         "dcid": "0101",
         "protocol_type": "QUIC_HTTP3",
         "reference_time": "0",
         "scid": ""
       },
       "configuration": {
         "time_offset": 0,
         "time_units": "us"
       },
       "description": "Generated qlog from connection",
       "event_fields": [
         "relative_time",
         "category",
         "event",
         "data"
       ],
       "events": [
         [
           "31",
           "transport",
           "packet_received",
           {
             "frames": [
               {
                 "fin": true,
                 "frame_type": "stream",
                 "stream_id": "10",
                 "length": 0,
                 "offset": 0
               }
             ],
             "header": {
               "packet_number": 1,
               "packet_size": 10
             },
             "packet_type": "1RTT"
           }
         ]
       ],
       "title": "mvfst qlog from single connection",
       "vantage_point": {
         "name": "server",
         "type": "server"
       }
     }
   ],
   "summary": {
     "max_duration": 0,
     "total_event_count": 1,
     "trace_count": 1
   }
 })");

  auto headerIn =
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(1), 1);
  RegularQuicPacket regularQuicPacket(std::move(headerIn));
  ReadStreamFrame frame(streamId, offset, fin);

  regularQuicPacket.frames.emplace_back(std::move(frame));
  auto dir = folly::fs::temp_directory_path().string();

  auto* q = new FileQLogger(
      VantagePoint::Server,
      kHTTP3ProtocolType,
      dir,
      true /* prettyJson */,
      true /* streaming */);

  folly::Random::DefaultGenerator rng;
  rng.seed(
      std::chrono::high_resolution_clock::now().time_since_epoch().count());

  q->setDcid(ConnectionId(std::vector<uint8_t>{
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
  }));
  q->addPacket(regularQuicPacket, 10);
  EXPECT_EQ(q->logs.size(), 0);

  std::string outputPath =
      folly::to<std::string>(dir, "/", (q->dcid.value()).hex(), ".qlog");
  delete q;

  std::ifstream file(outputPath, std::ifstream::in);
  std::string str(
      (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  folly::dynamic parsed = folly::parseJson(str);

  parsed["traces"][0]["events"][0][0] = "31"; // hardcode reference time
  parsed["traces"][0]["common_fields"]["dcid"] = "0101";

  EXPECT_EQ(expected, parsed);
}

const std::string expectedJsonStr1 =
    R"({
   "description": "Converted from file",
   "qlog_version": "draft-00",
   "summary": {
     "max_duration": 0,
     "total_event_count": 1,
     "trace_count": 1
   },
   "title": "mvfst qlog",
   "traces": [
     {
       "common_fields": {
         "dcid": "0202",
         "protocol_type": "QUIC_HTTP3",
         "reference_time": "0",
         "scid": ""
       },
       "configuration": {
         "time_offset": 0,
         "time_units": "us"
       },
       "description": "Generated qlog from connection",
       "event_fields": [
         "relative_time",
         "category",
         "event",
         "data"
       ],
       "events": [
         [
           "31",
           "transport",
           "packet_received",
           {
             "frames": [
               {
                 "fin": true,
                 "frame_type": "stream",
                 "stream_id": "10",
                 "length": 0,
                 "offset": 0
               }
             ],
             "header": {
               "packet_number": 1,
               "packet_size": 10
             },
             "packet_type": "1RTT"
           }
         ]
       ],
       "title": "mvfst qlog from single connection",
       "vantage_point": {
         "name": "server",
         "type": "server"
       }
     }
   ]
 })";

TEST_F(QLoggerTest, NonPrettyStream) {
  folly::dynamic expected = folly::parseJson(expectedJsonStr1);

  auto headerIn =
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(1), 1);
  RegularQuicPacket regularQuicPacket(std::move(headerIn));
  ReadStreamFrame frame(streamId, offset, fin);

  regularQuicPacket.frames.emplace_back(std::move(frame));
  auto dir = folly::fs::temp_directory_path().string();

  auto* q = new FileQLogger(
      VantagePoint::Server,
      kHTTP3ProtocolType,
      dir,
      false /* prettyJson */,
      true /* streaming */);

  folly::Random::DefaultGenerator rng;
  rng.seed(
      std::chrono::high_resolution_clock::now().time_since_epoch().count());

  q->setDcid(ConnectionId(std::vector<uint8_t>{
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
  }));
  q->addPacket(regularQuicPacket, 10);
  EXPECT_EQ(q->logs.size(), 0);

  std::string outputPath =
      folly::to<std::string>(dir, "/", (q->dcid.value()).hex(), ".qlog");
  delete q;

  std::ifstream file(outputPath, std::ifstream::in);
  std::string str(
      (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  folly::dynamic parsed = folly::parseJson(str);

  parsed["traces"][0]["events"][0][0] = "31"; // hardcode reference time
  parsed["traces"][0]["common_fields"]["dcid"] = "0202";

  EXPECT_EQ(expected["summary"], parsed["summary"]);
  EXPECT_EQ(expected["traces"], parsed["traces"]);
  std::string s;
  EXPECT_EQ((bool)getline(file, s), false);
}

TEST_F(QLoggerTest, CompressedStream) {
  folly::dynamic expected = folly::parseJson(expectedJsonStr1);

  auto headerIn =
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(1), 1);
  RegularQuicPacket regularQuicPacket(std::move(headerIn));
  ReadStreamFrame frame(streamId, offset, fin);

  regularQuicPacket.frames.emplace_back(std::move(frame));
  auto dir = folly::fs::temp_directory_path().string();

  auto* q = new FileQLogger(
      VantagePoint::Server,
      kHTTP3ProtocolType,
      dir,
      false /* prettyJson */,
      true /* streaming */,
      true /* compress */);

  q->setDcid(ConnectionId::createRandom(8));
  q->addPacket(regularQuicPacket, 10);
  // Streaming. Packet has been immediately logged.
  EXPECT_EQ(q->logs.size(), 0);

  std::string outputPath =
      folly::to<std::string>(dir, "/", (q->dcid.value()).hex(), ".qlog.gz");
  LOG(INFO) << outputPath;
  delete q;

  std::string compressedData;
  auto success = folly::readFile(outputPath.c_str(), compressedData);
  ASSERT_TRUE(success);

  std::string str = folly::io::getCodec(folly::io::CodecType::GZIP)
                        ->uncompress(compressedData);
  folly::dynamic parsed = folly::parseJson(str);

  parsed["traces"][0]["events"][0][0] = "31"; // hardcode reference time
  parsed["traces"][0]["common_fields"]["dcid"] = "0202";

  EXPECT_EQ(expected["summary"], parsed["summary"]);
  EXPECT_EQ(expected["traces"], parsed["traces"]);
}

TEST_F(QLoggerTest, CompressedNonStream) {
  folly::dynamic expected = folly::parseJson(expectedJsonStr1);

  auto headerIn =
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(1), 1);
  RegularQuicPacket regularQuicPacket(std::move(headerIn));
  ReadStreamFrame frame(streamId, offset, fin);

  regularQuicPacket.frames.emplace_back(std::move(frame));
  auto dir = folly::fs::temp_directory_path().string();

  FileQLogger q(
      VantagePoint::Server,
      kHTTP3ProtocolType,
      dir,
      false /* prettyJson */,
      false /* streaming */,
      true /* compress */);

  q.setDcid(ConnectionId::createRandom(8));
  q.addPacket(regularQuicPacket, 10);
  // Not streaming. Packet has not been logged yet.
  EXPECT_EQ(q.logs.size(), 1);

  q.outputLogsToFile(dir, false);

  std::string outputPath =
      folly::to<std::string>(dir, "/", (q.dcid.value()).hex(), ".qlog.gz");

  std::string compressedData;
  auto success = folly::readFile(outputPath.c_str(), compressedData);
  ASSERT_TRUE(success);

  std::string str = folly::io::getCodec(folly::io::CodecType::GZIP)
                        ->uncompress(compressedData);
  folly::dynamic parsed = folly::parseJson(str);

  parsed["traces"][0]["events"][0][0] = "31"; // hardcode reference time
  parsed["traces"][0]["common_fields"]["dcid"] = "0202";

  EXPECT_EQ(expected["summary"], parsed["summary"]);
  EXPECT_EQ(expected["traces"], parsed["traces"]);
}

TEST_F(QLoggerTest, NoThrowOnStreamingWithNonExistentDirectory) {
  auto headerIn =
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(1), 1);
  RegularQuicPacket regularQuicPacket(std::move(headerIn));
  ReadStreamFrame frame(streamId, offset, fin);

  regularQuicPacket.frames.emplace_back(std::move(frame));
  auto dir = std::tmpnam(nullptr);
  // Output directory does not exist.
  ASSERT_FALSE(folly::fs::exists(dir));

  auto* q = new FileQLogger(
      VantagePoint::Server,
      kHTTP3ProtocolType,
      dir,
      false /* prettyJson */,
      true /* streaming */,
      true /* compress */);

  EXPECT_NO_THROW(q->setDcid(ConnectionId::createRandom(8)));
  q->addPacket(regularQuicPacket, 10);
  EXPECT_EQ(
      q->logs.size(),
      0); // Packet is not written but also not being kept in memory

  std::string outputPath =
      folly::to<std::string>(dir, "/", (q->dcid.value()).hex(), ".qlog.gz");

  delete q;

  // Output file was not created
  EXPECT_FALSE(folly::fs::exists(outputPath));
}

TEST_F(QLoggerTest, PrettyDatagram) {
  folly::dynamic expected = folly::parseJson(
      R"({
   "description": "Converted from file",
   "qlog_version": "draft-00",
   "title": "mvfst qlog",
   "traces": [
     {
       "common_fields": {
         "dcid": "0101",
         "protocol_type": "QUIC_HTTP3",
         "reference_time": "0",
         "scid": ""
       },
       "configuration": {
         "time_offset": 0,
         "time_units": "us"
       },
       "description": "Generated qlog from connection",
       "event_fields": [
         "relative_time",
         "category",
         "event",
         "data"
       ],
       "events": [
         [
           "31",
           "transport",
           "packet_received",
           {
             "frames": [
               {
                 "frame_type": "datagram",
                 "length": 10
               }
             ],
             "header": {
               "packet_number": 1,
               "packet_size": 10
             },
             "packet_type": "1RTT"
           }
         ]
       ],
       "title": "mvfst qlog from single connection",
       "vantage_point": {
         "name": "server",
         "type": "server"
       }
     }
   ],
   "summary": {
     "max_duration": 0,
     "total_event_count": 1,
     "trace_count": 1
   }
 })");

  auto headerIn =
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(1), 1);
  RegularQuicPacket regularQuicPacket(std::move(headerIn));
  auto buf = folly::IOBuf::copyBuffer("0123456789");
  auto len = buf->computeChainDataLength();
  DatagramFrame frame(len, std::move(buf));

  regularQuicPacket.frames.emplace_back(std::move(frame));
  auto dir = folly::fs::temp_directory_path().string();

  auto* q = new FileQLogger(
      VantagePoint::Server,
      kHTTP3ProtocolType,
      dir,
      true /* prettyJson */,
      true /* streaming */);

  folly::Random::DefaultGenerator rng;
  rng.seed(
      std::chrono::high_resolution_clock::now().time_since_epoch().count());

  q->setDcid(ConnectionId(std::vector<uint8_t>{
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
      static_cast<uint8_t>(
          folly::Random::rand32(0, std::numeric_limits<uint8_t>::max(), rng)),
  }));
  q->addPacket(regularQuicPacket, 10);
  EXPECT_EQ(q->logs.size(), 0);

  std::string outputPath =
      folly::to<std::string>(dir, "/", (q->dcid.value()).hex(), ".qlog");
  delete q;

  std::ifstream file(outputPath, std::ifstream::in);
  std::string str(
      (std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
  folly::dynamic parsed = folly::parseJson(str);

  parsed["traces"][0]["events"][0][0] = "31"; // hardcode reference time
  parsed["traces"][0]["common_fields"]["dcid"] = "0101";

  EXPECT_EQ(expected, parsed);
}

} // namespace quic::test
