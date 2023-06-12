/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/DefaultConnectionIdAlgo.h>

#include <folly/Random.h>
#include <folly/portability/GTest.h>
#include <bitset>

namespace quic::test {

TEST(DefaultConnectionIdAlgoTest, canParse) {
  DefaultConnectionIdAlgo al;
  // version 0
  EXPECT_FALSE(al.canParse(ConnectionId({0x00, 0x01, 0x02, 0x03})));
  // version 1
  EXPECT_TRUE(al.canParse(ConnectionId({0x40, 0x01, 0x02, 0x03})));
  // version 2
  EXPECT_TRUE(al.canParse(ConnectionId({0x80, 0x01, 0x02, 0x03, 0x04, 0x05})));
  // version 3
  EXPECT_TRUE(
      al.canParse(ConnectionId({0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06})));
  // version 1, too small size
  EXPECT_FALSE(al.canParse(ConnectionId({0x40, 0x01, 0x02})));
  // version 2, too small size
  EXPECT_FALSE(al.canParse(ConnectionId({0x80, 0x01, 0x02, 0x03, 0x04})));
  // version 3, too small size
  EXPECT_FALSE(al.canParse(ConnectionId({0xc0, 0x01, 0x02, 0x03, 0x04, 0x05})));
}

TEST(DefaultConnectionIdAlgoTest, decodeV1) {
  DefaultConnectionIdAlgo al;
  std::bitset<32> b(
      std::string(/*version*/ "01" /*host*/ "1111111111111111" /*worker*/
                              "10101010" /*process*/ "1" /*unused*/ "00000"));
  uint32_t t = b.to_ulong();
  std::vector<uint8_t> v(4);
  v[0] = t >> 24;
  v[1] = t >> 16;
  v[2] = t >> 8;
  v[3] = t;
  ConnectionId cid1(v);
  EXPECT_TRUE(al.canParse(cid1));
  auto params1 = al.parseConnectionId(cid1);
  EXPECT_EQ(params1->version, ConnectionIdVersion::V1);
  EXPECT_EQ(params1->hostId, 0xFFFF);
  EXPECT_EQ(params1->workerId, 0xAA);
  EXPECT_EQ(params1->processId, 1);
}

TEST(DefaultConnectionIdAlgoTest, decodeV2) {
  DefaultConnectionIdAlgo al;
  ConnectionId cid1(
      {/*version*/ 0x80,
       /*host*/ 0xAA,
       0xBB,
       0xCC,
       /*worker*/ 0xFF,
       /*process*/ 0x80});
  EXPECT_TRUE(al.canParse(cid1));
  auto params1 = al.parseConnectionId(cid1);
  EXPECT_EQ(params1->version, ConnectionIdVersion::V2);
  EXPECT_EQ(params1->hostId, 0xAABBCC);
  EXPECT_EQ(params1->workerId, 0xFF);
  EXPECT_EQ(params1->processId, 1);
}

TEST(DefaultConnectionIdAlgoTest, decodeV3) {
  DefaultConnectionIdAlgo al;
  ConnectionId cid1(
      {/*version*/ 0xc0,
       /*host*/ 0xAA,
       0xBB,
       0xCC,
       0xDD,
       /*worker*/ 0xFF,
       /*process*/ 0x80});
  EXPECT_TRUE(al.canParse(cid1));
  auto params1 = al.parseConnectionId(cid1);
  EXPECT_EQ(params1->version, ConnectionIdVersion::V3);
  EXPECT_EQ(params1->hostId, 0xAABBCCDD);
  EXPECT_EQ(params1->workerId, 0xFF);
  EXPECT_EQ(params1->processId, 1);
}

TEST(DefaultConnectionIdAlgoTest, encodeDecode) {
  DefaultConnectionIdAlgo al;
  for (uint8_t i = 0; i <= 254; i++) {
    uint8_t processId = i % 2;
    uint32_t hostId = folly::Random::rand32();
    ServerConnectionIdParams params(hostId, processId, i);
    auto paramsAfterEncode =
        al.parseConnectionId(*al.encodeConnectionId(params));
    EXPECT_TRUE(al.canParse(*al.encodeConnectionId(params)));
    // in CID v1 lower 16 bits are used for host ID
    EXPECT_EQ(paramsAfterEncode->hostId, hostId & 0x0000FFFF);
    EXPECT_EQ(paramsAfterEncode->workerId, i);
    EXPECT_EQ(paramsAfterEncode->processId, processId);

    ServerConnectionIdParams params2(
        ConnectionIdVersion::V2, hostId, processId, i);
    auto paramsAfterEncode2 =
        al.parseConnectionId(*al.encodeConnectionId(params2));
    EXPECT_TRUE(al.canParse(*al.encodeConnectionId(params2)));
    // in CID v2 lower 24 bits are used for host ID
    EXPECT_EQ(paramsAfterEncode2->hostId, hostId & 0x00FFFFFF);
    EXPECT_EQ(paramsAfterEncode2->workerId, i);
    EXPECT_EQ(paramsAfterEncode2->processId, processId);

    ServerConnectionIdParams params3(
        ConnectionIdVersion::V3, hostId, processId, i);
    auto paramsAfterEncode3 =
        al.parseConnectionId(*al.encodeConnectionId(params3));
    EXPECT_TRUE(al.canParse(*al.encodeConnectionId(params3)));
    // in CID v3 server id is 32-bit
    EXPECT_EQ(paramsAfterEncode3->hostId, hostId);
    EXPECT_EQ(paramsAfterEncode3->workerId, i);
    EXPECT_EQ(paramsAfterEncode3->processId, processId);
  }
}

} // namespace quic::test
