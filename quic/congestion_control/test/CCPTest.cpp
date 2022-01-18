/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <chrono>
#include <thread>

#define MSS 1232

namespace quic::test {

/*
class QuicCCPTest : public Test {
};
*/

#ifdef CCP_ENABLED
TEST(CCPTest, TestFallback) {
  folly::ScopedEventBaseThread evbThread_;
  QuicCcpThreadLauncher launcher;

  EXPECT_FALSE(launcher.hasLaunched());

  evbThread_.getEventBase()->waitUntilRunning();

  std::unique_ptr<CCPReader> reader = std::make_unique<CCPReader>();
  evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
    reader->try_initialize(evbThread_.getEventBase(), 0, 0, 0);
    auto ret = reader->connect();
    EXPECT_LT(ret, 0);
    reader->start();
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  std::unique_ptr<CCP> ccp;
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
    conn.ccpDatapath = reader->getDatapath();
    conn.lossState.srtt = 50us;
    ccp = std::make_unique<CCP>(conn);
    EXPECT_EQ(
        ccp->getCongestionWindow(),
        conn.transportSettings.initCwndInMss * conn.udpSendPacketLen);
    EXPECT_EQ(conn.lossState.inflightBytes, 0);
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
    auto packet1 = makeTestingWritePacket(10, MSS, MSS);
    ccp->onPacketSent(packet1);
    EXPECT_EQ(conn.lossState.inflightBytes, MSS);
    auto packet2 = makeTestingWritePacket(20, MSS, MSS);
    ccp->onPacketSent(packet2);
    EXPECT_EQ(conn.lossState.inflightBytes, MSS * 2);
    auto packet3 = makeTestingWritePacket(30, MSS, MSS);
    ccp->onPacketSent(packet3);
    EXPECT_EQ(conn.lossState.inflightBytes, MSS * 3);
    ccp->onPacketAckOrLoss(
        makeAck(10, MSS, Clock::now(), packet1.metadata.time), folly::none);
    EXPECT_EQ(conn.lossState.inflightBytes, MSS * 2);
    ccp->onPacketAckOrLoss(
        makeAck(20, MSS, Clock::now(), packet2.metadata.time), folly::none);
    EXPECT_EQ(conn.lossState.inflightBytes, MSS * 1);
    ccp->onPacketAckOrLoss(
        makeAck(30, MSS, Clock::now(), packet3.metadata.time), folly::none);
    EXPECT_EQ(conn.lossState.inflightBytes, 0);
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(500));

  evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
    ccp.reset();
    auto manual = reader.release();
    delete manual;
  });
}

#define xstr(s) str(s)
#define str(s) #s
#define FIXED_CWND_TEST 100
#define INIT_CWND 10

TEST(CCPTest, TestSimple) {
  folly::ScopedEventBaseThread evbThread_;
  QuicCcpThreadLauncher launcher;

  evbThread_.getEventBase()->waitUntilRunning();

  std::string ccpConfig =
      std::string("constant --cwnd=") + std::string(xstr(FIXED_CWND_TEST));
  launcher.start(ccpConfig);

  std::this_thread::sleep_for(std::chrono::milliseconds(500));
  EXPECT_TRUE(launcher.hasLaunched());

  std::unique_ptr<CCPReader> reader = std::make_unique<CCPReader>();
  evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
    reader->try_initialize(
        evbThread_.getEventBase(), launcher.getCcpId(), 0, 0);
    auto ret = reader->connect();
    EXPECT_GE(ret, 0);
    reader->start();
  });

  std::unique_ptr<CCP> ccp;
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
    conn.ccpDatapath = reader->getDatapath();
    conn.lossState.srtt = 50us;
    ccp = std::make_unique<CCP>(conn);
    EXPECT_EQ(ccp->getCongestionWindow(), INIT_CWND * conn.udpSendPacketLen);
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
    auto packet1 = makeTestingWritePacket(10, MSS, MSS);
    ccp->onPacketSent(packet1);
    auto packet2 = makeTestingWritePacket(20, MSS, MSS);
    ccp->onPacketSent(packet2);
    auto packet3 = makeTestingWritePacket(30, MSS, MSS);
    ccp->onPacketSent(packet3);
    EXPECT_EQ(ccp->getCongestionWindow(), INIT_CWND * conn.udpSendPacketLen);
    EXPECT_EQ(conn.lossState.inflightBytes, MSS * 3);
    ccp->onPacketAckOrLoss(
        makeAck(10, MSS, Clock::now(), packet1.metadata.time), folly::none);
    EXPECT_EQ(
        ccp->getCongestionWindow(), FIXED_CWND_TEST * conn.udpSendPacketLen);
    ccp->onPacketAckOrLoss(
        makeAck(20, MSS, Clock::now(), packet2.metadata.time), folly::none);
    ccp->onPacketAckOrLoss(
        makeAck(30, MSS, Clock::now(), packet3.metadata.time), folly::none);
    EXPECT_EQ(conn.lossState.inflightBytes, 0);
    EXPECT_EQ(
        ccp->getCongestionWindow(), FIXED_CWND_TEST * conn.udpSendPacketLen);
  });

  std::this_thread::sleep_for(std::chrono::milliseconds(1000));

  evbThread_.getEventBase()->runInEventBaseThreadAndWait([&] {
    ccp.reset();
    auto manual = reader.release();
    delete manual;
  });

  launcher.stop();
}
#endif

} // namespace quic::test
