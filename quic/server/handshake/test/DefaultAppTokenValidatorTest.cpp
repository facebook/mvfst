/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/handshake/DefaultAppTokenValidator.h>

#include <quic/QuicConstants.h>
#include <quic/api/test/Mocks.h>
#include <quic/fizz/server/handshake/AppToken.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/test/MockQuicStats.h>

#include <fizz/server/ResumptionState.h>
#include <folly/Optional.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace fizz::server;
using namespace testing;

namespace quic {
namespace test {

TEST(DefaultAppTokenValidatorTest, TestValidParams) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  conn.transportSettings.zeroRttSourceTokenMatchingPolicy =
      ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni);
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) { return true; };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttAccepted());
  EXPECT_CALL(*quicStats, onZeroRttRejected()).Times(0);
  EXPECT_TRUE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestValidOptionalParameter) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  conn.transportSettings.zeroRttSourceTokenMatchingPolicy =
      ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni);
  appToken.transportParams.parameters.push_back(
      encodeIntegerParameter(TransportParameterId::disable_migration, 1));
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) { return true; };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttAccepted()).Times(1);
  EXPECT_CALL(*quicStats, onZeroRttRejected()).Times(0);
  EXPECT_TRUE(validator.validate(resState));
}

TEST(
    DefaultAppTokenValidatorTest,
    TestValidUnequalParamsUpdateTransportSettings) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  conn.transportSettings.zeroRttSourceTokenMatchingPolicy =
      ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  auto initialMaxData =
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow;
  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      initialMaxData - 1,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni);
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) { return true; };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttRejected()).Times(0);
  EXPECT_CALL(*quicStats, onZeroRttAccepted());
  EXPECT_TRUE(validator.validate(resState));

  EXPECT_EQ(
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      initialMaxData - 1);
  EXPECT_EQ(conn.flowControlState.windowSize, initialMaxData - 1);
  EXPECT_EQ(conn.flowControlState.advertisedMaxOffset, initialMaxData - 1);
}

TEST(DefaultAppTokenValidatorTest, TestInvalidNullAppToken) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;

  ResumptionState resState;
  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) {
    EXPECT_TRUE(false);
    return true;
  };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestInvalidEmptyTransportParams) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  AppToken appToken;
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) {
    EXPECT_TRUE(false);
    return true;
  };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttAccepted()).Times(0);
  EXPECT_CALL(*quicStats, onZeroRttRejected());
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestInvalidMissingParams) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  AppToken appToken;
  auto& params = appToken.transportParams;
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      conn.transportSettings
          .advertisedInitialBidiLocalStreamFlowControlWindow));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote,
      conn.transportSettings
          .advertisedInitialBidiRemoteStreamFlowControlWindow));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::ack_delay_exponent,
      conn.transportSettings.ackDelayExponent));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::max_packet_size,
      conn.transportSettings.maxRecvPacketSize));

  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) {
    EXPECT_TRUE(false);
    return true;
  };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttAccepted()).Times(0);
  EXPECT_CALL(*quicStats, onZeroRttRejected());
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestInvalidRedundantParameter) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni);
  appToken.transportParams.parameters.push_back(
      encodeIntegerParameter(TransportParameterId::idle_timeout, 100));
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) {
    EXPECT_TRUE(false);
    return true;
  };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttAccepted()).Times(0);
  EXPECT_CALL(*quicStats, onZeroRttRejected());
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestInvalidDecreasedInitialMaxStreamData) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow +
          1,
      conn.transportSettings
              .advertisedInitialBidiRemoteStreamFlowControlWindow +
          1,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow + 1,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni);
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) {
    EXPECT_TRUE(false);
    return true;
  };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestChangedIdleTimeout) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count() + 100,
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni);
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) {
    EXPECT_TRUE(false);
    return true;
  };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttAccepted()).Times(0);
  EXPECT_CALL(*quicStats, onZeroRttRejected());
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestDecreasedInitialMaxStreams) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi + 1,
      conn.transportSettings.advertisedInitialMaxStreamsUni + 1);
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) {
    EXPECT_TRUE(false);
    return true;
  };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttAccepted()).Times(0);
  EXPECT_CALL(*quicStats, onZeroRttRejected());
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestInvalidAppParams) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  MockConnectionSetupCallback connSetupCallback;
  MockConnectionCallback connCallback;

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni);
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) { return false; };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_FALSE(validator.validate(resState));
}

class SourceAddressTokenTest : public Test {
 public:
  SourceAddressTokenTest()
      : conn_(FizzServerQuicHandshakeContext::Builder().build()) {}

  void SetUp() override {
    conn_.peerAddress = folly::SocketAddress("1.2.3.4", 443);
    conn_.version = QuicVersion::MVFST;

    appToken_.transportParams = createTicketTransportParameters(
        conn_.transportSettings.idleTimeout.count(),
        conn_.transportSettings.maxRecvPacketSize,
        conn_.transportSettings.advertisedInitialConnectionFlowControlWindow,
        conn_.transportSettings
            .advertisedInitialBidiLocalStreamFlowControlWindow,
        conn_.transportSettings
            .advertisedInitialBidiRemoteStreamFlowControlWindow,
        conn_.transportSettings.advertisedInitialUniStreamFlowControlWindow,
        conn_.transportSettings.advertisedInitialMaxStreamsBidi,
        conn_.transportSettings.advertisedInitialMaxStreamsUni);
  }

  void encodeAndValidate(bool acceptZeroRtt = true) {
    ResumptionState resState;
    resState.appToken = encodeAppToken(appToken_);

    conn_.earlyDataAppParamsValidator = [=](const folly::Optional<std::string>&,
                                            const Buf&) {
      return acceptZeroRtt;
    };
    DefaultAppTokenValidator validator(&conn_);
    EXPECT_EQ(validator.validate(resState), acceptZeroRtt);
  }

 protected:
  QuicServerConnectionState conn_;
  AppToken appToken_;
};

class LimitIfNoMatchPolicyTest : public SourceAddressTokenTest {
 public:
  void SetUp() override {
    SourceAddressTokenTest::SetUp();
    conn_.transportSettings.zeroRttSourceTokenMatchingPolicy =
        ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;
  }
};

TEST_F(LimitIfNoMatchPolicyTest, EmptySourceToken) {
  encodeAndValidate();

  EXPECT_EQ(
      conn_.writableBytesLimit.value(),
      conn_.transportSettings.limitedCwndInMss * conn_.udpSendPacketLen);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(conn_.peerAddress.getIPAddress()));
  EXPECT_FALSE(conn_.isClientAddrVerified);
}

TEST_F(LimitIfNoMatchPolicyTest, OneSourceTokenNoAddrMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.5")};
  encodeAndValidate();

  EXPECT_EQ(
      conn_.writableBytesLimit.value(),
      conn_.transportSettings.limitedCwndInMss * conn_.udpSendPacketLen);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.5"), conn_.peerAddress.getIPAddress()));
  EXPECT_FALSE(conn_.isClientAddrVerified);
}

TEST_F(LimitIfNoMatchPolicyTest, OneSourceTokenAddrMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.4")};
  encodeAndValidate();

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(conn_.peerAddress.getIPAddress()));
  EXPECT_TRUE(conn_.isClientAddrVerified);
}

TEST_F(LimitIfNoMatchPolicyTest, MaxNumSourceTokenNoAddrMatch) {
  appToken_.sourceAddresses = {
      folly::IPAddress("1.2.3.5"),
      folly::IPAddress("1.2.3.6"),
      folly::IPAddress("1.2.3.7")};
  encodeAndValidate();

  EXPECT_EQ(
      conn_.writableBytesLimit.value(),
      conn_.transportSettings.limitedCwndInMss * conn_.udpSendPacketLen);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.6"),
          folly::IPAddress("1.2.3.7"),
          conn_.peerAddress.getIPAddress()));
  EXPECT_FALSE(conn_.isClientAddrVerified);
}

TEST_F(LimitIfNoMatchPolicyTest, MaxNumSourceTokenAddrMatch) {
  appToken_.sourceAddresses = {
      folly::IPAddress("1.2.3.5"),
      folly::IPAddress("1.2.3.4"),
      folly::IPAddress("1.2.3.7")};
  encodeAndValidate();

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.5"),
          folly::IPAddress("1.2.3.7"),
          conn_.peerAddress.getIPAddress()));
  EXPECT_TRUE(conn_.isClientAddrVerified);
}

class RejectIfNoMatchPolicyTest : public SourceAddressTokenTest {
 public:
  void SetUp() override {
    SourceAddressTokenTest::SetUp();
    conn_.transportSettings.zeroRttSourceTokenMatchingPolicy =
        ZeroRttSourceTokenMatchingPolicy::REJECT_IF_NO_EXACT_MATCH;
  }
};

TEST_F(RejectIfNoMatchPolicyTest, EmptySourceToken) {
  encodeAndValidate(false);

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(conn_.peerAddress.getIPAddress()));
}

TEST_F(RejectIfNoMatchPolicyTest, OneSourceTokenNoAddrMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.5")};
  encodeAndValidate(false);

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.5"), conn_.peerAddress.getIPAddress()));
  EXPECT_FALSE(conn_.isClientAddrVerified);
}

TEST_F(RejectIfNoMatchPolicyTest, OneSourceTokenAddrMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.4")};
  encodeAndValidate();

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(conn_.peerAddress.getIPAddress()));
  EXPECT_TRUE(conn_.isClientAddrVerified);
}

TEST_F(RejectIfNoMatchPolicyTest, MaxNumSourceTokenNoAddrMatch) {
  appToken_.sourceAddresses = {
      folly::IPAddress("1.2.3.5"),
      folly::IPAddress("1.2.3.6"),
      folly::IPAddress("1.2.3.7")};
  encodeAndValidate(false);

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.6"),
          folly::IPAddress("1.2.3.7"),
          conn_.peerAddress.getIPAddress()));
  EXPECT_FALSE(conn_.isClientAddrVerified);
}

TEST_F(RejectIfNoMatchPolicyTest, MaxNumSourceTokenAddrMatch) {
  appToken_.sourceAddresses = {
      folly::IPAddress("1.2.3.5"),
      folly::IPAddress("1.2.3.4"),
      folly::IPAddress("1.2.3.7")};

  encodeAndValidate();

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.5"),
          folly::IPAddress("1.2.3.7"),
          conn_.peerAddress.getIPAddress()));
  EXPECT_TRUE(conn_.isClientAddrVerified);
}

class AlwaysRejectPolicyTest : public SourceAddressTokenTest {
 public:
  void SetUp() override {
    SourceAddressTokenTest::SetUp();
    conn_.transportSettings.zeroRttSourceTokenMatchingPolicy =
        ZeroRttSourceTokenMatchingPolicy::ALWAYS_REJECT;
  }
};

TEST_F(AlwaysRejectPolicyTest, EmptySourceToken) {
  encodeAndValidate(false);

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(conn_.peerAddress.getIPAddress()));
  EXPECT_FALSE(conn_.isClientAddrVerified);
}

TEST_F(AlwaysRejectPolicyTest, OneSourceTokenNoAddrMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.5")};
  encodeAndValidate(false);

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.5"), conn_.peerAddress.getIPAddress()));
  EXPECT_FALSE(conn_.isClientAddrVerified);
}

TEST_F(AlwaysRejectPolicyTest, OneSourceTokenAddrMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.4")};
  encodeAndValidate(false);

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(conn_.peerAddress.getIPAddress()));
  EXPECT_TRUE(conn_.isClientAddrVerified);
}

TEST_F(AlwaysRejectPolicyTest, MaxNumSourceTokenNoAddrMatch) {
  appToken_.sourceAddresses = {
      folly::IPAddress("1.2.3.5"),
      folly::IPAddress("1.2.3.6"),
      folly::IPAddress("1.2.3.7")};
  encodeAndValidate(false);

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.6"),
          folly::IPAddress("1.2.3.7"),
          conn_.peerAddress.getIPAddress()));
  EXPECT_FALSE(conn_.isClientAddrVerified);
}

TEST_F(AlwaysRejectPolicyTest, MaxNumSourceTokenAddrMatch) {
  appToken_.sourceAddresses = {
      folly::IPAddress("1.2.3.5"),
      folly::IPAddress("1.2.3.4"),
      folly::IPAddress("1.2.3.7")};

  encodeAndValidate(false);

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.5"),
          folly::IPAddress("1.2.3.7"),
          conn_.peerAddress.getIPAddress()));
  EXPECT_TRUE(conn_.isClientAddrVerified);
}

} // namespace test
} // namespace quic
