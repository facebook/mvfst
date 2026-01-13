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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace fizz::server;
using namespace testing;

namespace quic::test {

// Test helper that implements EarlyDataAppParamsHandler with std::function
// for flexible test setup
class TestEarlyDataAppParamsHandler : public EarlyDataAppParamsHandler {
 public:
  bool validate(const Optional<std::string>& alpn, const BufPtr& params)
      override {
    return validateFn ? validateFn(alpn, params) : true;
  }

  BufPtr get() override {
    return getFn ? getFn() : nullptr;
  }

  std::function<bool(const Optional<std::string>&, const BufPtr&)> validateFn;
  std::function<BufPtr()> getFn;
};

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
  auto transportParamsResult = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni,
      conn.transportSettings.advertisedExtendedAckFeatures);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    return true;
  };
  conn.earlyDataAppParamsHandler = &handler;
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
  auto transportParamsResult = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni,
      conn.transportSettings.advertisedExtendedAckFeatures);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  auto disableMigrationResult =
      encodeIntegerParameter(TransportParameterId::disable_migration, 1);
  ASSERT_FALSE(disableMigrationResult.hasError());
  appToken.transportParams.parameters.push_back(disableMigrationResult.value());
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    return true;
  };
  conn.earlyDataAppParamsHandler = &handler;
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
  auto transportParamsResult = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      initialMaxData - 1,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni,
      conn.transportSettings.advertisedExtendedAckFeatures);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    return true;
  };
  conn.earlyDataAppParamsHandler = &handler;
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttRejected()).Times(0);
  EXPECT_CALL(*quicStats, onZeroRttAccepted());
  EXPECT_TRUE(validator.validate(resState));

  // Transport settings will not be updated by the ticket.
  EXPECT_EQ(
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      initialMaxData);
  EXPECT_EQ(conn.flowControlState.windowSize, initialMaxData);
  EXPECT_EQ(conn.flowControlState.advertisedMaxOffset, initialMaxData);
}

TEST(DefaultAppTokenValidatorTest, TestInvalidNullAppToken) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;

  ResumptionState resState;
  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    EXPECT_TRUE(false);
    return true;
  };
  conn.earlyDataAppParamsHandler = &handler;
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

  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    EXPECT_TRUE(false);
    return true;
  };
  conn.earlyDataAppParamsHandler = &handler;
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

  auto bidiLocalResult = encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow);
  ASSERT_FALSE(bidiLocalResult.hasError());
  params.parameters.push_back(bidiLocalResult.value());

  auto bidiRemoteResult = encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote,
      conn.transportSettings
          .advertisedInitialBidiRemoteStreamFlowControlWindow);
  ASSERT_FALSE(bidiRemoteResult.hasError());
  params.parameters.push_back(bidiRemoteResult.value());

  auto uniResult = encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow);
  ASSERT_FALSE(uniResult.hasError());
  params.parameters.push_back(uniResult.value());

  auto ackDelayResult = encodeIntegerParameter(
      TransportParameterId::ack_delay_exponent,
      conn.transportSettings.ackDelayExponent);
  ASSERT_FALSE(ackDelayResult.hasError());
  params.parameters.push_back(ackDelayResult.value());

  auto maxPacketSizeResult = encodeIntegerParameter(
      TransportParameterId::max_packet_size,
      conn.transportSettings.maxRecvPacketSize);
  ASSERT_FALSE(maxPacketSizeResult.hasError());
  params.parameters.push_back(maxPacketSizeResult.value());
  appToken.sourceAddresses = {conn.peerAddress.getIPAddress()};
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    EXPECT_TRUE(false);
    return true;
  };
  conn.earlyDataAppParamsHandler = &handler;
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttAccepted()).Times(0);
  EXPECT_CALL(*quicStats, onZeroRttRejected());
  EXPECT_FALSE(validator.validate(resState));
}

// This test was not actually testing for redundant parameters. It was passing
// because the check on the source address was invalidating the token.
// The validator currently allows redundant parameters.
// TODO: Update the validator to reject redundant parameters?
// TEST(DefaultAppTokenValidatorTest, TestInvalidRedundantParameter) {
//   QuicServerConnectionState conn(
//       FizzServerQuicHandshakeContext::Builder().build());
//   conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
//   conn.version = QuicVersion::MVFST;
//   auto quicStats = std::make_shared<MockQuicStats>();
//   conn.statsCallback = quicStats.get();

//   AppToken appToken;
//   appToken.transportParams = createTicketTransportParameters(
//       conn.transportSettings.idleTimeout.count(),
//       conn.transportSettings.maxRecvPacketSize,
//       conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
//       conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
//       conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
//       conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
//       conn.transportSettings.advertisedInitialMaxStreamsBidi,
//       conn.transportSettings.advertisedInitialMaxStreamsUni,
//       conn.transportSettings.advertisedExtendedAckFeatures);
//   appToken.transportParams.parameters.push_back(
//       encodeIntegerParameter(TransportParameterId::idle_timeout, 100));
//   appToken.sourceAddresses = {conn.peerAddress.getIPAddress()};
//   ResumptionState resState;
//   resState.appToken = encodeAppToken(appToken);

//   conn.earlyDataAppParamsValidator = [](const Optional<std::string>&,
//                                         const BufPtr&) {
//     EXPECT_TRUE(false);
//     return true;
//   };
//   DefaultAppTokenValidator validator(&conn);
//   EXPECT_CALL(*quicStats, onZeroRttAccepted()).Times(0);
//   EXPECT_CALL(*quicStats, onZeroRttRejected());
//   EXPECT_FALSE(validator.validate(resState));
// }

TEST(DefaultAppTokenValidatorTest, TestInvalidDecreasedInitialMaxStreamData) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
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
      conn.transportSettings.advertisedInitialMaxStreamsUni,
      conn.transportSettings.advertisedExtendedAckFeatures);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {conn.peerAddress.getIPAddress()};
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    EXPECT_TRUE(false);
    return true;
  };
  conn.earlyDataAppParamsHandler = &handler;
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
  auto transportParamsResult = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count() + 100,
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni,
      conn.transportSettings.advertisedExtendedAckFeatures);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {conn.peerAddress.getIPAddress()};
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    EXPECT_TRUE(false);
    return true;
  };
  conn.earlyDataAppParamsHandler = &handler;
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
  auto transportParamsResult = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi + 1,
      conn.transportSettings.advertisedInitialMaxStreamsUni + 1,
      conn.transportSettings.advertisedExtendedAckFeatures);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {conn.peerAddress.getIPAddress()};
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    EXPECT_TRUE(false);
    return true;
  };
  conn.earlyDataAppParamsHandler = &handler;
  DefaultAppTokenValidator validator(&conn);
  EXPECT_CALL(*quicStats, onZeroRttAccepted()).Times(0);
  EXPECT_CALL(*quicStats, onZeroRttRejected());
  EXPECT_FALSE(validator.validate(resState));
}

TEST(DefaultAppTokenValidatorTest, TestInvalidExtendedAckSupportChanged) {
  QuicServerConnectionState conn(
      FizzServerQuicHandshakeContext::Builder().build());
  conn.peerAddress = folly::SocketAddress("1.2.3.4", 443);
  conn.version = QuicVersion::MVFST;
  auto quicStats = std::make_shared<MockQuicStats>();
  conn.statsCallback = quicStats.get();

  AppToken appToken;
  auto transportParamsResult = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni,
      conn.transportSettings.advertisedExtendedAckFeatures + 1);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  appToken.sourceAddresses = {conn.peerAddress.getIPAddress()};
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    EXPECT_TRUE(false);
    return true;
  };
  conn.earlyDataAppParamsHandler = &handler;
  DefaultAppTokenValidator validator(&conn);
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
  auto transportParamsResult = createTicketTransportParameters(
      conn.transportSettings.idleTimeout.count(),
      conn.transportSettings.maxRecvPacketSize,
      conn.transportSettings.advertisedInitialConnectionFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiLocalStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialBidiRemoteStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialUniStreamFlowControlWindow,
      conn.transportSettings.advertisedInitialMaxStreamsBidi,
      conn.transportSettings.advertisedInitialMaxStreamsUni,
      conn.transportSettings.advertisedExtendedAckFeatures);
  ASSERT_FALSE(transportParamsResult.hasError());
  appToken.transportParams = std::move(transportParamsResult.value());
  auto idleTimeoutResult =
      encodeIntegerParameter(TransportParameterId::idle_timeout, 100);
  ASSERT_FALSE(idleTimeoutResult.hasError());
  appToken.transportParams.parameters.push_back(idleTimeoutResult.value());
  appToken.sourceAddresses = {conn.peerAddress.getIPAddress()};
  ResumptionState resState;
  resState.appToken = encodeAppToken(appToken);

  TestEarlyDataAppParamsHandler handler;
  handler.validateFn = [](const Optional<std::string>&, const BufPtr&) {
    return false;
  };
  conn.earlyDataAppParamsHandler = &handler;
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

    auto transportParamsResult = createTicketTransportParameters(
        conn_.transportSettings.idleTimeout.count(),
        conn_.transportSettings.maxRecvPacketSize,
        conn_.transportSettings.advertisedInitialConnectionFlowControlWindow,
        conn_.transportSettings
            .advertisedInitialBidiLocalStreamFlowControlWindow,
        conn_.transportSettings
            .advertisedInitialBidiRemoteStreamFlowControlWindow,
        conn_.transportSettings.advertisedInitialUniStreamFlowControlWindow,
        conn_.transportSettings.advertisedInitialMaxStreamsBidi,
        conn_.transportSettings.advertisedInitialMaxStreamsUni,
        conn_.transportSettings.advertisedExtendedAckFeatures);
    ASSERT_FALSE(transportParamsResult.hasError());
    appToken_.transportParams = std::move(transportParamsResult.value());
  }

  void encodeAndValidate(bool acceptZeroRtt = true) {
    ResumptionState resState;
    resState.appToken = encodeAppToken(appToken_);

    handler_.validateFn = [=](const Optional<std::string>&, const BufPtr&) {
      return acceptZeroRtt;
    };
    conn_.earlyDataAppParamsHandler = &handler_;
    DefaultAppTokenValidator validator(&conn_);
    EXPECT_EQ(validator.validate(resState), acceptZeroRtt);
  }

 protected:
  QuicServerConnectionState conn_;
  AppToken appToken_;
  TestEarlyDataAppParamsHandler handler_;
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

} // namespace quic::test
