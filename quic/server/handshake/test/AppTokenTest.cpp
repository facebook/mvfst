/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/server/handshake/AppToken.h>

#include <quic/QuicConstants.h>
#include <quic/server/state/ServerStateMachine.h>

#include <fizz/server/ResumptionState.h>
#include <folly/Optional.h>

#include <gtest/gtest.h>

#include <cstdint>

namespace quic {
namespace test {

void expectAppTokenEqual(
    const folly::Optional<AppToken>& decodedAppToken,
    const AppToken& appToken) {
  EXPECT_TRUE(decodedAppToken.has_value());

  EXPECT_EQ(
      decodedAppToken->transportParams.parameters.size(),
      appToken.transportParams.parameters.size());

  EXPECT_GE(
      decodedAppToken->transportParams.parameters.size(),
      kMinimumNumOfParamsInTheTicket);
  // TODO Split out into individual flow control parameters.
  auto maxStreamData = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      decodedAppToken->transportParams.parameters);
  auto expectedMaxStreamData = getIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      appToken.transportParams.parameters);
  EXPECT_EQ(maxStreamData, expectedMaxStreamData);

  auto maxData = getIntegerParameter(
      TransportParameterId::initial_max_data,
      decodedAppToken->transportParams.parameters);
  auto expectedMaxData = getIntegerParameter(
      TransportParameterId::initial_max_data,
      appToken.transportParams.parameters);
  EXPECT_EQ(maxData, expectedMaxData);

  auto idleTimeout = getIntegerParameter(
      TransportParameterId::idle_timeout,
      decodedAppToken->transportParams.parameters);
  auto expectedIdleTimeout = getIntegerParameter(
      TransportParameterId::idle_timeout, appToken.transportParams.parameters);
  EXPECT_EQ(idleTimeout, expectedIdleTimeout);

  auto maxRecvPacketSize = getIntegerParameter(
      TransportParameterId::max_packet_size,
      decodedAppToken->transportParams.parameters);
  auto expectedMaxRecvPacketSize = getIntegerParameter(
      TransportParameterId::max_packet_size,
      appToken.transportParams.parameters);
  EXPECT_EQ(maxRecvPacketSize, expectedMaxRecvPacketSize);

  auto ackDelayExponent = getIntegerParameter(
      TransportParameterId::ack_delay_exponent,
      decodedAppToken->transportParams.parameters);
  auto expectedAckDelayExponent = getIntegerParameter(
      TransportParameterId::ack_delay_exponent,
      appToken.transportParams.parameters);
  EXPECT_EQ(ackDelayExponent, expectedAckDelayExponent);

  EXPECT_EQ(
      decodedAppToken->sourceAddresses.size(), appToken.sourceAddresses.size());
  for (size_t ii = 0; ii < appToken.sourceAddresses.size(); ++ii) {
    EXPECT_EQ(
        decodedAppToken->sourceAddresses[ii], appToken.sourceAddresses[ii]);
  }

  EXPECT_NE(decodedAppToken->appParams, nullptr);
  if (appToken.appParams) {
    EXPECT_TRUE(folly::IOBufEqualTo()(
        *decodedAppToken->appParams, *appToken.appParams));
  } else {
    EXPECT_EQ(decodedAppToken->appParams->computeChainDataLength(), 0);
  }
}

TEST(AppTokenTest, TestEncodeAndDecodeNoSourceAddresses) {
  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max());
  appToken.version = QuicVersion::MVFST;
  Buf buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeSingleIPv6Address) {
  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max());
  appToken.sourceAddresses = {
      folly::IPAddress("2401:db00:2111:7283:face::46:0")};
  appToken.version = QuicVersion::MVFST;
  Buf buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeThreeIPv6Addresses) {
  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max());
  appToken.sourceAddresses = {
      folly::IPAddress("2401:db00:2111:7283:face::46:0"),
      folly::IPAddress("2401:db00:2111:7283:face::46:1"),
      folly::IPAddress("2401:db00:2111:7283:face::46:2")};
  appToken.version = QuicVersion::MVFST;
  Buf buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeSingleIPv4Address) {
  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max());
  appToken.sourceAddresses = {folly::IPAddress("1.2.3.4")};
  appToken.version = QuicVersion::MVFST;
  Buf buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeThreeIPv4Addresses) {
  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max());
  appToken.sourceAddresses = {
      folly::IPAddress("1.2.3.4"),
      folly::IPAddress("1.2.3.5"),
      folly::IPAddress("1.2.3.6")};
  appToken.version = QuicVersion::MVFST;
  Buf buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeIPv6AndIPv4Addresses) {
  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max());
  appToken.sourceAddresses = {
      folly::IPAddress("2401:db00:2111:7283:face::46:0"),
      folly::IPAddress("1.2.3.4"),
      folly::IPAddress("2401:db00:2111:7283:face::46:2")};
  appToken.version = QuicVersion::MVFST;
  Buf buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeWithAppToken) {
  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max());
  appToken.appParams = folly::IOBuf::copyBuffer("QPACK Params");
  appToken.version = QuicVersion::MVFST;
  Buf buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

TEST(AppTokenTest, TestEncodeAndDecodeIPv6AndIPv4AddressesWithAppToken) {
  AppToken appToken;
  appToken.transportParams = createTicketTransportParameters(
      kDefaultIdleTimeout.count(),
      kDefaultUDPReadBufferSize,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max());
  appToken.sourceAddresses = {
      folly::IPAddress("2401:db00:2111:7283:face::46:0"),
      folly::IPAddress("1.2.3.4"),
      folly::IPAddress("2401:db00:2111:7283:face::46:2")};
  appToken.appParams = folly::IOBuf::copyBuffer("QPACK Params");
  appToken.version = QuicVersion::MVFST;
  Buf buf = encodeAppToken(appToken);

  expectAppTokenEqual(decodeAppToken(*buf), appToken);
}

} // namespace test
} // namespace quic
