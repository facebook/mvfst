/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/handshake/DefaultAppTokenValidator.h>

#include <quic/QuicConstants.h>
#include <quic/api/test/Mocks.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>

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

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionWindowSize,
      conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize,
      conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize,
      conn.transportSettings.advertisedInitialUniStreamWindowSize,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni);
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) { return true; };
  DefaultAppTokenValidator validator(&conn);
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

  auto initialMaxData =
      conn.transportSettings.advertisedInitialConnectionWindowSize;
  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      initialMaxData - 1,
      conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize,
      conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize,
      conn.transportSettings.advertisedInitialUniStreamWindowSize,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni);
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  conn.earlyDataAppParamsValidator = [](const folly::Optional<std::string>&,
                                        const Buf&) { return true; };
  DefaultAppTokenValidator validator(&conn);
  EXPECT_TRUE(validator.validate(resState));

  EXPECT_EQ(
      conn.transportSettings.advertisedInitialConnectionWindowSize,
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

  AppToken appToken;
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

TEST(DefaultAppTokenValidatorTest, TestInvalidMissingParams) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;

  AppToken appToken;
  auto& params = appToken.transportParams;
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote,
      conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni,
      conn.transportSettings.advertisedInitialUniStreamWindowSize));
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
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestInvalidRedundantParameter) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionWindowSize,
      conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize,
      conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize,
      conn.transportSettings.advertisedInitialUniStreamWindowSize,
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
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestInvalidDecreasedInitialMaxStreamData) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionWindowSize,
      conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize + 1,
      conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize + 1,
      conn.transportSettings.advertisedInitialUniStreamWindowSize + 1,
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

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count() + 100,
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionWindowSize,
      conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize,
      conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize,
      conn.transportSettings.advertisedInitialUniStreamWindowSize,
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

TEST(DefaultAppTokenValidatorTest, TestDecreasedInitialMaxStreams) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionWindowSize,
      conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize,
      conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize,
      conn.transportSettings.advertisedInitialUniStreamWindowSize,
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
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestInvalidAppParams) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;

  MockConnectionCallback connCallback;

  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionWindowSize,
      conn.transportSettings.advertisedInitialBidiLocalStreamWindowSize,
      conn.transportSettings.advertisedInitialBidiRemoteStreamWindowSize,
      conn.transportSettings.advertisedInitialUniStreamWindowSize,
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
    conn_.transportSettings.zeroRttSourceTokenMatchingPolicy =
        ZeroRttSourceTokenMatchingPolicy::LIMIT_IF_NO_EXACT_MATCH;

    appToken_.transportParams = createTicketTransportParameters(
        conn_.transportSettings.idleTimeout.count(),
        conn_.transportSettings.maxRecvPacketSize,
        conn_.transportSettings.advertisedInitialConnectionWindowSize,
        conn_.transportSettings.advertisedInitialBidiLocalStreamWindowSize,
        conn_.transportSettings.advertisedInitialBidiRemoteStreamWindowSize,
        conn_.transportSettings.advertisedInitialUniStreamWindowSize,
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

TEST_F(SourceAddressTokenTest, EmptySourceToken) {
  encodeAndValidate();

  EXPECT_EQ(
      conn_.writableBytesLimit.value(),
      conn_.transportSettings.limitedCwndInMss * conn_.udpSendPacketLen);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(conn_.peerAddress.getIPAddress()));
}

TEST_F(SourceAddressTokenTest, OneSourceTokensNoMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.5")};
  encodeAndValidate();

  EXPECT_EQ(
      conn_.writableBytesLimit.value(),
      conn_.transportSettings.limitedCwndInMss * conn_.udpSendPacketLen);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.5"), conn_.peerAddress.getIPAddress()));
}

TEST_F(SourceAddressTokenTest, MaxNumSourceTokensNoMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.5"),
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
}

TEST_F(SourceAddressTokenTest, OneSourceTokensMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.4")};
  encodeAndValidate();

  EXPECT_FALSE(conn_.writableBytesLimit);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(conn_.peerAddress.getIPAddress()));
}

TEST_F(SourceAddressTokenTest, ThreeSourceTokensMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.5"),
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
}

class SourceAddressTokenRejectNoMatchPolicyTest
    : public SourceAddressTokenTest {
 public:
  void SetUp() override {
    SourceAddressTokenTest::SetUp();
    conn_.transportSettings.zeroRttSourceTokenMatchingPolicy =
        ZeroRttSourceTokenMatchingPolicy::REJECT_IF_NO_EXACT_MATCH;
  }
};

TEST_F(SourceAddressTokenRejectNoMatchPolicyTest, EmptySourceToken) {
  encodeAndValidate(false);
  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(conn_.peerAddress.getIPAddress()));
}

TEST_F(SourceAddressTokenRejectNoMatchPolicyTest, OneSourceTokensNoMatch) {
  appToken_.sourceAddresses = {folly::IPAddress("1.2.3.5")};
  encodeAndValidate(false);

  ASSERT_THAT(
      conn_.tokenSourceAddresses,
      ElementsAre(
          folly::IPAddress("1.2.3.5"), conn_.peerAddress.getIPAddress()));
}
} // namespace test
} // namespace quic
