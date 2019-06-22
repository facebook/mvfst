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
  RegularQuicWritePacket regularWritePacket =
      createRegularQuicWritePacket(streamId, offset, len, fin);

  FileQLogger q;
  q.add(regularWritePacket, 10);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketEvent*>(p.get());
  auto gotObject = *static_cast<StreamFrameLog*>(gotEvent->frames[0].get());

  EXPECT_EQ(gotObject.streamId, streamId);
  EXPECT_EQ(gotObject.offset, offset);
  EXPECT_EQ(gotObject.fin, fin);
}

TEST_F(QLoggerTest, TestRegularPacket) {
  auto expected = folly::IOBuf::copyBuffer("hello");
  auto packet = createStreamPacket(
      getTestConnectionId(0),
      getTestConnectionId(1),
      1,
      streamId,
      *expected,
      0 /* cipherOverhead */,
      0 /* largestAcked */,
      folly::none /* longHeaderOverride */,
      fin,
      folly::none /* shortHeaderOverride */,
      offset);

  auto regularQuicPacket = packet.packet;
  FileQLogger q;
  q.add(regularQuicPacket, 10);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogPacketEvent*>(p.get());
  auto gotObject = *static_cast<StreamFrameLog*>(gotEvent->frames[0].get());

  EXPECT_EQ(gotObject.streamId, streamId);
  EXPECT_EQ(gotObject.offset, offset);
  EXPECT_EQ(gotObject.fin, fin);
}

TEST_F(QLoggerTest, TestVersionNegotiationPacket) {
  bool isPacketRecvd = false;
  FileQLogger q;
  auto packet = createVersionNegotiationPacket();
  q.add(packet, 10, isPacketRecvd);

  std::unique_ptr<QLogEvent> p = std::move(q.logs[0]);
  auto gotEvent = dynamic_cast<QLogVersionNegotiationEvent*>(p.get());
  auto gotObject = *gotEvent->versionLog.get();

  EXPECT_EQ(gotObject.versions, packet.versions);
}

TEST_F(QLoggerTest, RegularPacketFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"({
        "traces": [
          {"event_fields":[
              "CATEGORY",
              "EVENT_TYPE",
              "TRIGGER",
              "DATA"
            ],
            "events":[
               [
                "TRANSPORT",
                "PACKET_SENT",
                "DEFAULT",
                {
                  "packet_type": "INITIAL",
                  "header":{
                    "packet_number":10,
                    "packet_size":10},
                  "frames":[
                    {"frame_type":"STREAM",
                    "id":10,
                    "fin":true,
                    "length":0,
                    "offset":0
                    }
                  ]
                }
              ]
            ]
          }
        ]
      })");

  RegularQuicWritePacket packet =
      createRegularQuicWritePacket(streamId, offset, len, fin);

  FileQLogger q;
  q.add(packet, 10);
  folly::dynamic gotDynamic = q.toDynamic();

  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, RegularPacketAckFrameFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"({
   "traces": [
     {
       "event_fields": [
         "CATEGORY",
         "EVENT_TYPE",
         "TRIGGER",
         "DATA"
       ],
       "events": [
         [
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
  q.add(packet, 1001);
  folly::dynamic gotDynamic = q.toDynamic();

  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, VersionPacketFollyDynamic) {
  folly::dynamic expected = folly::parseJson(
      R"({
           "traces": [
             {
               "event_fields": [
                 "CATEGORY",
                 "EVENT_TYPE",
                 "TRIGGER",
                 "DATA"
               ],
               "events": [
                 [
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
  q.add(packet, 10, isPacketRecvd);
  folly::dynamic gotDynamic = q.toDynamic();

  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, AddingMultiplePacketEvents) {
  auto buf = folly::IOBuf::copyBuffer("hello");
  folly::dynamic expected = folly::parseJson(
      R"( {
   "traces": [
     {
       "event_fields": [
         "CATEGORY",
         "EVENT_TYPE",
         "TRIGGER",
         "DATA"
       ],
       "events": [
         [
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

  q.add(versionPacket, 10, isPacketRecvd);
  q.add(regPacket, 100);
  q.add(regularQuicPacket, 10);

  folly::dynamic gotDynamic = q.toDynamic();

  EXPECT_EQ(expected, gotDynamic);
}

TEST_F(QLoggerTest, AddingMultipleFrames) {
  folly::dynamic expected = folly::parseJson(
      R"( {
   "traces": [
     {
       "event_fields": [
         "CATEGORY",
         "EVENT_TYPE",
         "TRIGGER",
         "DATA"
       ],
       "events": [
         [
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

  q.add(packet, 10);
  folly::dynamic gotDynamic = q.toDynamic();

  EXPECT_EQ(expected, gotDynamic);
}

} // namespace quic::test
