/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/logging/QLogger.h>

#include <folly/json.h>
#include <gtest/gtest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/congestion_control/Bbr.h>
#include <quic/logging/FileQLogger.h>

using namespace quic;
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

  FileQLogger q(fakeProtocolType);
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
  RegularQuicPacket regularQuicPacket(headerIn);
  ReadStreamFrame frame(streamId, offset, fin);

  regularQuicPacket.frames.emplace_back(std::move(frame));

  FileQLogger q;
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
  FileQLogger q;
  auto packet = createVersionNegotiationPacket();
  q.addPacket(packet, 10, isPacketRecvd);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogVersionNegotiationEvent*>(p.get());
  auto gotObject = *gotEvent->versionLog.get();

  EXPECT_EQ(gotObject.versions, packet.versions);
}

TEST_F(QLoggerTest, ConnectionCloseEvent) {
  FileQLogger q;
  auto error = toString(LocalErrorCode::CONNECTION_RESET);
  q.addConnectionClose(error, "Connection close", true, false);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogConnectionCloseEvent*>(p.get());
  EXPECT_EQ(gotEvent->error, error);
  EXPECT_EQ(gotEvent->drainConnection, true);
  EXPECT_EQ(gotEvent->sendCloseImmediately, false);
}

TEST_F(QLoggerTest, TransportSummaryEvent) {
  FileQLogger q;
  q.addTransportSummary(8, 9, 5, 3, 2, 554, 100, 32, 134, 238);

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
}

TEST_F(QLoggerTest, CongestionMetricUpdateEvent) {
  FileQLogger q;
  q.addCongestionMetricUpdate(
      20,
      30,
      kPersistentCongestion.str(),
      cubicStateToString(CubicStates::Steady).str(),
      bbrRecoveryStateToString(
          BbrCongestionController::RecoveryState::NOT_RECOVERY));

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogCongestionMetricUpdateEvent*>(p.get());

  EXPECT_EQ(gotEvent->bytesInFlight, 20);
  EXPECT_EQ(gotEvent->currentCwnd, 30);
  EXPECT_EQ(gotEvent->congestionEvent, kPersistentCongestion.str());
  EXPECT_EQ(gotEvent->state, cubicStateToString(CubicStates::Steady).str());
  EXPECT_EQ(
      gotEvent->recoveryState,
      bbrRecoveryStateToString(
          BbrCongestionController::RecoveryState::NOT_RECOVERY));
}

TEST_F(QLoggerTest, PacingMetricUpdateEvent) {
  FileQLogger q;
  q.addPacingMetricUpdate(10, 30us);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacingMetricUpdateEvent*>(p.get());

  EXPECT_EQ(gotEvent->pacingBurstSize, 10);
  EXPECT_EQ(gotEvent->pacingInterval, 30us);
}

TEST_F(QLoggerTest, AppIdleUpdateEvent) {
  FileQLogger q;
  q.addAppIdleUpdate(kAppIdle.str(), false);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogAppIdleUpdateEvent*>(p.get());

  EXPECT_EQ(gotEvent->idleEvent, kAppIdle.str());
  EXPECT_FALSE(gotEvent->idle);
}

TEST_F(QLoggerTest, PacketDropEvent) {
  FileQLogger q;
  q.addPacketDrop(5, kCipherUnavailable.str());

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketDropEvent*>(p.get());

  EXPECT_EQ(gotEvent->packetSize, 5);
  EXPECT_EQ(gotEvent->dropReason, kCipherUnavailable.str());
}

TEST_F(QLoggerTest, DatagramReceivedEvent) {
  FileQLogger q;
  q.addDatagramReceived(100);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogDatagramReceivedEvent*>(p.get());

  EXPECT_EQ(gotEvent->dataLen, 100);
}

TEST_F(QLoggerTest, LossAlarmEvent) {
  FileQLogger q;
  q.addLossAlarm(PacketNum{1}, 3983, 893, kPtoAlarm.str());

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogLossAlarmEvent*>(p.get());

  EXPECT_EQ(gotEvent->largestSent, 1);
  EXPECT_EQ(gotEvent->alarmCount, 3983);
  EXPECT_EQ(gotEvent->outstandingPackets, 893);
  EXPECT_EQ(gotEvent->type, kPtoAlarm.str());
}

TEST_F(QLoggerTest, PacketsLostEvent) {
  FileQLogger q;
  q.addPacketsLost(PacketNum{42}, 332, 89);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketsLostEvent*>(p.get());

  EXPECT_EQ(gotEvent->largestLostPacketNum, 42);
  EXPECT_EQ(gotEvent->lostBytes, 332);
  EXPECT_EQ(gotEvent->lostPackets, 89);
}

TEST_F(QLoggerTest, TransportStateUpdateEvent) {
  FileQLogger q;
  std::string update = "start";
  q.addTransportStateUpdate(update);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogTransportStateUpdateEvent*>(p.get());

  EXPECT_EQ(gotEvent->update, update);
}

TEST_F(QLoggerTest, RegularPacketFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"({
   "traces": [
     {
       "common_fields": {
         "dcid": "",
         "protocol_type": "QUIC_HTTP3",
         "reference_time": "0",
         "scid": ""
       },
       "event_fields": [
         "relative_time",
         "category",
         "event_type",
         "trigger",
         "data"
       ],
       "events": [
         [
           "0",
           "TRANSPORT",
           "PACKET_RECEIVED",
           "DEFAULT",
           {
             "frames": [
               {
                 "fin": true,
                 "frame_type": "STREAM",
                 "id": 10,
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
       ]
     }
   ]
  })");

  auto headerIn =
      ShortHeader(ProtectionType::KeyPhaseZero, getTestConnectionId(1), 1);
  RegularQuicPacket regularQuicPacket(headerIn);
  ReadStreamFrame frame(streamId, offset, fin);

  regularQuicPacket.frames.emplace_back(std::move(frame));

  FileQLogger q;
  q.addPacket(regularQuicPacket, 10);

  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, RegularWritePacketFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"({
     "traces": [
       {
         "common_fields": {
           "dcid": "4000000304050607",
           "protocol_type": "QUIC_HTTP3",
           "reference_time": "0",
           "scid": "4000400304050607"
         },
         "event_fields": [
           "relative_time",
           "category",
           "event_type",
           "trigger",
           "data"
         ],
         "events": [
           [
             "0",
             "TRANSPORT",
             "PACKET_SENT",
             "DEFAULT",
             {
               "frames": [
                 {
                   "fin": true,
                   "frame_type": "STREAM",
                   "id": 10,
                   "length": 0,
                   "offset": 0
                 }
               ],
               "header": {
                 "packet_number": 10,
                 "packet_size": 10
               },
               "packet_type": "INITIAL"
             }
           ]
         ]
       }
     ]
  })");

  RegularQuicWritePacket packet =
      createRegularQuicWritePacket(streamId, offset, len, fin);

  FileQLogger q;
  q.dcid = getTestConnectionId(0);
  q.scid = getTestConnectionId(1);
  q.addPacket(packet, 10);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, RegularPacketAckFrameFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"({
   "traces": [
     {
       "common_fields": {
         "dcid": "",
         "protocol_type": "QUIC_HTTP3",
         "reference_time": "0",
         "scid": ""
       },
       "event_fields": [
         "relative_time",
         "category",
         "event_type",
         "trigger",
         "data"
       ],
       "events": [
         [
           "0",
           "TRANSPORT",
           "PACKET_SENT",
           "DEFAULT",
           {
             "frames": [
               {
                 "ack_delay": 111,
                 "acked_ranges": [
                  [
                    500,
                    700
                  ],
                  [
                    900,
                    1000
                  ]
                 ],
                 "frame_type": "ACK"
               }
             ],
             "header": {
               "packet_number": 100,
               "packet_size": 1001
             },
             "packet_type": "INITIAL"
           }
         ]
       ]
     }
   ]
 })");

  RegularQuicWritePacket packet = createPacketWithAckFrames();
  FileQLogger q;
  q.addPacket(packet, 1001);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, VersionPacketFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"({
           "traces": [
             {
              "common_fields": {
                "reference_time": "0",
                "dcid": "4000000304050607",
                "protocol_type": "QUIC_HTTP3",
                "scid": "4000400304050607"
              },
              "event_fields": [
                "relative_time",
                "category",
                "event_type",
                "trigger",
                "data"
              ],
               "events": [
                 [
                   "0",
                   "TRANSPORT",
                   "PACKET_SENT",
                   "DEFAULT",
                   {
                     "header": {
                       "packet_size": 10
                     },
                     "packet_type": "VersionNegotiation",
                      "versions": [
                        "VERSION_NEGOTIATION",
                        "MVFST"
                      ]
                   }
                 ]
               ]
             }
           ]
         })");

  auto packet = createVersionNegotiationPacket();
  FileQLogger q;
  q.dcid = getTestConnectionId(0);
  q.scid = getTestConnectionId(1);
  q.addPacket(packet, 10, isPacketRecvd);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, AddingMultiplePacketEvents) {
  auto buf = folly::IOBuf::copyBuffer("hello");
  folly::dynamic expected = folly::parseJson(
      R"( {
   "traces": [
     {
      "common_fields": {
         "dcid": "",
         "protocol_type": "QUIC_HTTP3",
         "reference_time": "0",
         "scid": ""
       },
       "event_fields": [
         "relative_time",
         "category",
         "event_type",
         "trigger",
         "data"
       ],
       "events": [
         [
          "0",
          "TRANSPORT",
           "PACKET_SENT",
           "DEFAULT",
           {
             "header": {
               "packet_size": 10
             },
             "packet_type": "VersionNegotiation",
             "versions": [
               "VERSION_NEGOTIATION",
               "MVFST"
             ]
           }
         ],
         [
           "1",
           "TRANSPORT",
           "PACKET_SENT",
           "DEFAULT",
           {
             "frames": [
               {
                 "ack_delay": 111,
                 "acked_ranges": [
                   [
                     500,
                     700
                   ],
                   [
                     900,
                     1000
                   ]
                 ],
                 "frame_type": "ACK"
               }
             ],
             "header": {
               "packet_number": 100,
               "packet_size": 100
             },
             "packet_type": "INITIAL"
           }
         ],
         [
           "2",
           "TRANSPORT",
           "PACKET_SENT",
           "DEFAULT",
           {
             "frames": [
               {
                 "fin": true,
                 "frame_type": "STREAM",
                 "id": 10,
                 "length": 5,
                 "offset": 0
               },
               {
                 "frame_type": "PADDING"
               },
               {
                 "frame_type": "PADDING"
               },
               {
                 "frame_type": "PADDING"
               },
               {
                 "frame_type": "PADDING"
               },
               {
                 "frame_type": "PADDING"
               },
               {
                 "frame_type": "PADDING"
               },
               {
                 "frame_type": "PADDING"
               },
               {
                 "frame_type": "PADDING"
               },
               {
                 "frame_type": "PADDING"
               },
               {
                 "frame_type": "PADDING"
               },
               {
                 "frame_type": "PADDING"
               }
             ],
             "header": {
               "packet_number": 1,
               "packet_size": 10
             },
             "packet_type": "1RTT"
           }
         ]
       ]
     }
   ]
 })");

  FileQLogger q;
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
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  gotDynamic["traces"][0]["events"][1][0] = "1"; // hardcode reference time
  gotDynamic["traces"][0]["events"][2][0] = "2"; // hardcode reference time

  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, AddingMultipleFrames) {
  folly::dynamic expected = folly::parseJson(
      R"( {
   "traces": [
     {
      "common_fields": {
        "dcid": "",
        "protocol_type": "QUIC_HTTP3",
        "reference_time": "0",
        "scid": ""
       },
       "event_fields": [
         "relative_time",
         "category",
         "event_type",
         "trigger",
         "data"
       ],
       "events": [
         [
           "0",
           "TRANSPORT",
           "PACKET_SENT",
           "DEFAULT",
           {
             "frames": [
               {
                 "ack_delay": 111,
                 "acked_ranges": [
                   [
                     100,
                     200
                   ],
                   [
                     300,
                     400
                   ]
                 ],
                 "frame_type": "ACK"
               },
               {
                 "fin": true,
                 "frame_type": "STREAM",
                 "id": 10,
                 "length": 0,
                 "offset": 0
               }
             ],
             "header": {
               "packet_number": 100,
               "packet_size": 10
             },
             "packet_type": "INITIAL"
           }
         ]
       ]
     }
  ]
  })");

  FileQLogger q;
  RegularQuicWritePacket packet =
      createNewPacket(100, PacketNumberSpace::Initial);

  WriteAckFrame ackFrame;
  ackFrame.ackDelay = 111us;
  ackFrame.ackBlocks.insert(100, 200);
  ackFrame.ackBlocks.insert(300, 400);
  WriteStreamFrame streamFrame(streamId, offset, len, fin);

  packet.frames.emplace_back(std::move(ackFrame));
  packet.frames.emplace_back(std::move(streamFrame));

  q.addPacket(packet, 10);
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, ConnectionCloseFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"([[
           "0",
           "CONNECTIVITY",
           "CONNECTION_CLOSE",
           "DEFAULT",
           {
             "drain_connection": true,
             "error": "Connection reset",
             "reason": "Connection changed",
             "send_close_immediately": false
           }
         ]])");

  FileQLogger q;
  auto error = toString(LocalErrorCode::CONNECTION_RESET);
  q.addConnectionClose(error, "Connection changed", true, false);
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
     "TRANSPORT",
     "TRANSPORT_SUMMARY",
     "DEFAULT",
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
       "total_crypto_data_recvd": 10
     }
   ]
 ])");

  FileQLogger q;
  q.addTransportSummary(1, 2, 3, 4, 5, 6, 7, 8, 9, 10);
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
        "METRIC_UPDATE",
        "CONGESTION_METRIC_UPDATE",
        "DEFAULT",
        {
          "bytes_in_flight": 20,
          "congestion_event": "persistent congestion",
          "current_cwnd": 30,
          "recovery_state": "",
          "state": "Steady"
        }
      ]
 ])");

  FileQLogger q;
  q.addCongestionMetricUpdate(
      20,
      30,
      kPersistentCongestion.str(),
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
        "METRIC_UPDATE",
        "PACING_METRIC_UPDATE",
        "DEFAULT",
        {
         "pacing_burst_size": 20,
         "pacing_interval": 30
        }
      ]
 ])");

  FileQLogger q;
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
        "IDLE_UPDATE",
        "APP_IDLE_UPDATE",
        "DEFAULT",
        {
         "idle_event": "app idle",
         "idle": true
        }
      ]
 ])");

  FileQLogger q;
  q.addAppIdleUpdate(kAppIdle.str(), true);
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
        "LOSS",
        "PACKET_DROP",
        "DEFAULT",
        {
         "drop_reason": "max buffered",
         "packet_size": 100
        }
      ]
 ])");

  FileQLogger q;
  q.addPacketDrop(100, kMaxBuffered.str());
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
       "TRANSPORT",
       "DATAGRAM_RECEIVED",
       "DEFAULT",
       {
         "data_len": 8
       }
      ]
 ])");

  FileQLogger q;
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
       "LOSS",
       "LOSS_ALARM",
       "DEFAULT",
       {
         "largest_sent": 100,
         "alarm_count": 14,
         "outstanding_packets": 38,
         "type": "handshake alarm"
       }
      ]
 ])");

  FileQLogger q;
  q.addLossAlarm(PacketNum{100}, 14, 38, kHandshakeAlarm.str());
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
       "LOSS",
       "PACKETS_LOST",
       "DEFAULT",
       {
         "largest_lost_packet_num": 10,
         "lost_bytes": 9,
         "lost_packets": 8
       }
      ]
 ])");

  FileQLogger q;
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
     "TRANSPORT",
     "TRANSPORT_STATE_UPDATE",
     "DEFAULT",
     {
       "update": "transport ready"
     }
    ]
])");

  FileQLogger q;
  q.addTransportStateUpdate("transport ready");
  folly::dynamic gotDynamic = q.toDynamic();
  gotDynamic["traces"][0]["events"][0][0] = "0"; // hardcode reference time
  folly::dynamic gotEvents = gotDynamic["traces"][0]["events"];
  EXPECT_EQ(expected, gotEvents);
}

} // namespace quic::test
