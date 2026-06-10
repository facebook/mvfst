/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/IPAddress.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/handshake/TransportParameters.h>
#include <quic/server/state/ServerStateMachine.h>

using namespace ::testing;

namespace quic::test {

class TransportParametersTest : public Test {
 protected:
  // Helper function that simulates client transport parameter generation
  // This mirrors what QuicClientTransportLite does - gets base params and adds
  // client-specific ones
  std::vector<TransportParameter> getClientTransportParams(
      const QuicClientConnectionState& conn) {
    auto params = getSupportedExtTransportParams(conn);
    if (conn.transportSettings.clientDirectEncapConfig) {
      auto maybeEncodedDirectEncapParam = encodeIntegerParameter(
          TransportParameterId::client_direct_encap,
          conn.transportSettings.clientDirectEncapConfig.value());
      // The encoding should succeed because *clientDirectEncapConfig is a
      // uint8_t
      CHECK(maybeEncodedDirectEncapParam)
          << "Failed to encode direct encap param";
      params.push_back(*maybeEncodedDirectEncapParam);
    }
    return params;
  }
};

// Test client-side direct encap parameter generation
TEST_F(TransportParametersTest, ClientDirectEncapEnabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.clientDirectEncapConfig = 0x04; // Zone 4

  auto customTransportParams = getClientTransportParams(clientConn);

  auto it = findParameter(
      customTransportParams, TransportParameterId::client_direct_encap);
  EXPECT_TRUE(it != customTransportParams.end());

  // Verify the parameter contains the zone value
  auto maybeZoneValue = getIntegerParameter(
      TransportParameterId::client_direct_encap, customTransportParams);
  ASSERT_FALSE(maybeZoneValue.hasError());
  ASSERT_TRUE(maybeZoneValue.value());
  EXPECT_EQ(*maybeZoneValue.value(), 0x04);
}

TEST_F(TransportParametersTest, ClientDirectEncapDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  // Don't set clientDirectEncapConfig (it's Optional, so it will be none)

  auto customTransportParams = getClientTransportParams(clientConn);

  EXPECT_THAT(
      customTransportParams,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::client_direct_encap)))));
}

// Test server-side direct encap parameter generation with IPv4
TEST_F(TransportParametersTest, ServerDirectEncapIPv4) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerDirectEncapConfig config;
  config.directEncapAddress = folly::IPAddress("192.168.1.1");
  config.supportedZones = 0x0F; // Supports zones 1, 2, 4, 8
  serverConn.transportSettings.serverDirectEncapConfig = config;

  // Create client parameters containing client_direct_encap with zone 4
  std::vector<TransportParameter> clientParams;
  auto clientDirectEncapParam = encodeIntegerParameter(
      TransportParameterId::client_direct_encap, 0x04); // Zone 4
  ASSERT_FALSE(clientDirectEncapParam.hasError());
  clientParams.push_back(clientDirectEncapParam.value());

  auto customTransportParams =
      getClientDependentExtTransportParams(serverConn, clientParams);

  auto it = findParameter(
      customTransportParams, TransportParameterId::server_direct_encap);
  EXPECT_TRUE(it != customTransportParams.end());
  EXPECT_EQ(it->value->length(), 4); // IPv4 is 4 bytes

  // Verify the IP address bytes
  auto expectedAddr = folly::IPAddress("192.168.1.1");
  auto expectedBytes = expectedAddr.bytes();
  auto actualRange = it->value->coalesce();
  EXPECT_EQ(actualRange.size(), 4);
  EXPECT_EQ(memcmp(actualRange.data(), expectedBytes, 4), 0);
}

// Test server-side direct encap parameter generation with IPv6
TEST_F(TransportParametersTest, ServerDirectEncapIPv6) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerDirectEncapConfig config;
  config.directEncapAddress = folly::IPAddress("2001:db8::1");
  config.supportedZones = 0x02; // Supports zone 2
  serverConn.transportSettings.serverDirectEncapConfig = config;

  // Create client parameters containing client_direct_encap with zone 2
  std::vector<TransportParameter> clientParams;
  auto clientDirectEncapParam = encodeIntegerParameter(
      TransportParameterId::client_direct_encap, 0x02); // Zone 2
  ASSERT_FALSE(clientDirectEncapParam.hasError());
  clientParams.push_back(clientDirectEncapParam.value());

  auto customTransportParams =
      getClientDependentExtTransportParams(serverConn, clientParams);

  auto it = findParameter(
      customTransportParams, TransportParameterId::server_direct_encap);
  EXPECT_TRUE(it != customTransportParams.end());
  EXPECT_EQ(it->value->length(), 16); // IPv6 is 16 bytes

  // Verify the IP address bytes
  auto expectedAddr = folly::IPAddress("2001:db8::1");
  auto expectedBytes = expectedAddr.bytes();
  auto actualRange = it->value->coalesce();
  EXPECT_EQ(actualRange.size(), 16);
  EXPECT_EQ(memcmp(actualRange.data(), expectedBytes, 16), 0);
}

// Test server doesn't send server_direct_encap when config not set
TEST_F(TransportParametersTest, ServerDirectEncapNoConfig) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  // Don't set serverDirectEncapConfig

  // Create client parameters containing client_direct_encap with zone 1
  std::vector<TransportParameter> clientParams;
  auto clientDirectEncapParam = encodeIntegerParameter(
      TransportParameterId::client_direct_encap, 0x01); // Zone 1
  ASSERT_FALSE(clientDirectEncapParam.hasError());
  clientParams.push_back(clientDirectEncapParam.value());

  auto customTransportParams =
      getClientDependentExtTransportParams(serverConn, clientParams);

  EXPECT_THAT(
      customTransportParams,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::server_direct_encap)))));
}

// Test server doesn't send server_direct_encap when client doesn't support it
TEST_F(TransportParametersTest, ServerDirectEncapClientNotSupported) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerDirectEncapConfig config;
  config.directEncapAddress = folly::IPAddress("192.168.1.1");
  config.supportedZones = 0x01; // Supports zone 1
  serverConn.transportSettings.serverDirectEncapConfig = config;

  // Create client parameters WITHOUT client_direct_encap
  std::vector<TransportParameter> clientParams;
  // Add some other parameter to make sure we're not just testing empty list
  auto paramResult =
      encodeIntegerParameter(TransportParameterId::idle_timeout, 5000);
  ASSERT_FALSE(paramResult.hasError());
  clientParams.push_back(paramResult.value());

  auto customTransportParams =
      getClientDependentExtTransportParams(serverConn, clientParams);

  EXPECT_THAT(
      customTransportParams,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::server_direct_encap)))));
}

// Test server doesn't send server_direct_encap when client zone doesn't match
TEST_F(TransportParametersTest, ServerDirectEncapZoneMismatch) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  ServerDirectEncapConfig config;
  config.directEncapAddress = folly::IPAddress("192.168.1.1");
  config.supportedZones = 0x0A; // Supports zones 2 and 8 (binary: 1010)
  serverConn.transportSettings.serverDirectEncapConfig = config;

  // Create client parameters with zone 4 (not supported by server)
  std::vector<TransportParameter> clientParams;
  auto clientDirectEncapParam = encodeIntegerParameter(
      TransportParameterId::client_direct_encap, 0x04); // Zone 4
  ASSERT_FALSE(clientDirectEncapParam.hasError());
  clientParams.push_back(clientDirectEncapParam.value());

  auto customTransportParams =
      getClientDependentExtTransportParams(serverConn, clientParams);

  // Server should not send direct encap param because zones don't match
  EXPECT_THAT(
      customTransportParams,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::server_direct_encap)))));
}

// Test IP address encoding helper function directly
TEST_F(TransportParametersTest, EncodeIPAddressParameterIPv4) {
  folly::IPAddress addr("10.0.0.1");
  auto param =
      encodeIPAddressParameter(TransportParameterId::server_direct_encap, addr);

  EXPECT_EQ(param.parameter, TransportParameterId::server_direct_encap);
  EXPECT_EQ(param.value->length(), 4);

  auto expectedBytes = addr.bytes();
  auto actualRange = param.value->coalesce();
  EXPECT_EQ(memcmp(actualRange.data(), expectedBytes, 4), 0);
}

TEST_F(TransportParametersTest, EncodeIPAddressParameterIPv6) {
  folly::IPAddress addr("::1");
  auto param =
      encodeIPAddressParameter(TransportParameterId::server_direct_encap, addr);

  EXPECT_EQ(param.parameter, TransportParameterId::server_direct_encap);
  EXPECT_EQ(param.value->length(), 16);

  auto expectedBytes = addr.bytes();
  auto actualRange = param.value->coalesce();
  EXPECT_EQ(memcmp(actualRange.data(), expectedBytes, 16), 0);
}

// Test SCONE transport parameter generation when enabled
TEST_F(TransportParametersTest, EncodeSconeTPWhenEnabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertiseSconeSupport = true;

  auto params = getSupportedExtTransportParams(serverConn);

  // Should contain SCONE supported parameter when enabled
  auto it = findParameter(params, TransportParameterId::scone_supported);
  EXPECT_TRUE(it != params.end());
  EXPECT_TRUE(it->value->empty()); // Zero-length value
}

// Test SCONE transport parameter omission when disabled
TEST_F(TransportParametersTest, OmitSconeTPWhenDisabled) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  serverConn.transportSettings.advertiseSconeSupport = false;

  auto params = getSupportedExtTransportParams(serverConn);

  // Should not contain SCONE supported parameter when disabled
  auto it = findParameter(params, TransportParameterId::scone_supported);
  EXPECT_TRUE(it == params.end());
}

// Test SCONE parameter round-trip helper functions
TEST_F(TransportParametersTest, RoundTripHelper) {
  // Test with SCONE parameter present
  auto encodedParam = encodeSconeSupportedParameter();
  std::vector<TransportParameter> vecWithScone = {encodedParam};
  EXPECT_TRUE(getSconeSupportedParameter(vecWithScone));

  // Test with empty vector
  std::vector<TransportParameter> emptyVec = {};
  EXPECT_FALSE(getSconeSupportedParameter(emptyVec));

  // Test with other parameters but no SCONE parameter
  std::vector<TransportParameter> vecWithoutScone;
  auto otherParam =
      encodeIntegerParameter(TransportParameterId::idle_timeout, 5000);
  ASSERT_FALSE(otherParam.hasError());
  vecWithoutScone.push_back(otherParam.value());
  EXPECT_FALSE(getSconeSupportedParameter(vecWithoutScone));
}

// Test SCONE parameter encoding/decoding - zero-length presence indicator
TEST_F(TransportParametersTest, SconeSupportedParameter) {
  // Test encoding - should create zero-length parameter
  auto encodedParam = encodeSconeSupportedParameter();
  EXPECT_EQ(encodedParam.parameter, TransportParameterId::scone_supported);
  EXPECT_EQ(encodedParam.value->length(), 0); // Zero-length value

  // Test decoding - presence check
  std::vector<TransportParameter> paramListWithScone = {encodedParam};
  std::vector<TransportParameter> paramListWithoutScone = {};

  // Should return true when parameter is present
  EXPECT_TRUE(getSconeSupportedParameter(paramListWithScone));

  // Should return false when parameter is absent
  EXPECT_FALSE(getSconeSupportedParameter(paramListWithoutScone));
}

// draft-ietf-quic-receive-ts-02 transport-parameter encoding. The two
// TransportSettings knobs `enableIetfAckReceiveTimestamps` and
// `advertiseLegacyAckReceiveTimestamps` gate the emitted TPs.

TEST_F(TransportParametersTest, EncodeDraft02TpsWhenIetfEnabledAndConfigSet) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto& ts = clientConn.transportSettings;
  ts.enableIetfAckReceiveTimestamps = true;
  ts.maybeAckReceiveTimestampsConfigSentToPeer = AckReceiveTimestampsConfig{
      .maxReceiveTimestampsPerAck = 7, .receiveTimestampsExponent = 3};

  auto params = getSupportedExtTransportParams(clientConn);

  auto maxParam = getIntegerParameter(
      TransportParameterId::draft_02_max_receive_timestamps_per_ack, params);
  ASSERT_FALSE(maxParam.hasError());
  ASSERT_TRUE(maxParam.value().has_value());
  EXPECT_EQ(*maxParam.value(), 7);

  auto expParam = getIntegerParameter(
      TransportParameterId::draft_02_receive_timestamps_exponent, params);
  ASSERT_FALSE(expParam.hasError());
  ASSERT_TRUE(expParam.value().has_value());
  EXPECT_EQ(*expParam.value(), 3);
}

TEST_F(TransportParametersTest, OmitDraft02TpsWhenIetfDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto& ts = clientConn.transportSettings;
  ts.enableIetfAckReceiveTimestamps = false; // default
  ts.maybeAckReceiveTimestampsConfigSentToPeer = AckReceiveTimestampsConfig{};

  auto params = getSupportedExtTransportParams(clientConn);

  EXPECT_THAT(
      params,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::draft_02_max_receive_timestamps_per_ack)))));
  EXPECT_THAT(
      params,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::draft_02_receive_timestamps_exponent)))));
}

TEST_F(TransportParametersTest, OmitDraft02TpsWhenIetfEnabledButConfigNotSet) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto& ts = clientConn.transportSettings;
  ts.enableIetfAckReceiveTimestamps = true;
  // No maybeAckReceiveTimestampsConfigSentToPeer: caller is not requesting
  // any receive timestamps from the peer.

  auto params = getSupportedExtTransportParams(clientConn);

  EXPECT_THAT(
      params,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::draft_02_max_receive_timestamps_per_ack)))));
  EXPECT_THAT(
      params,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::draft_02_receive_timestamps_exponent)))));
}

TEST_F(TransportParametersTest, OmitLegacyTpsWhenLegacyAdvertiseDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto& ts = clientConn.transportSettings;
  ts.advertiseLegacyAckReceiveTimestamps = false;
  ts.enableIetfAckReceiveTimestamps = true;
  ts.maybeAckReceiveTimestampsConfigSentToPeer = AckReceiveTimestampsConfig{
      .maxReceiveTimestampsPerAck = 6, .receiveTimestampsExponent = 4};

  auto params = getSupportedExtTransportParams(clientConn);

  // No legacy receive-timestamp TPs at all.
  EXPECT_THAT(
      params,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::ack_receive_timestamps_enabled)))));
  EXPECT_THAT(
      params,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::max_receive_timestamps_per_ack)))));
  EXPECT_THAT(
      params,
      Not(Contains(Field(
          &TransportParameter::parameter,
          Eq(TransportParameterId::receive_timestamps_exponent)))));

  // Draft-02 TPs are present with the configured values: guards against an
  // implementation that suppresses all receive-timestamp TPs when only the
  // legacy knob is off.
  auto draftMax = getIntegerParameter(
      TransportParameterId::draft_02_max_receive_timestamps_per_ack, params);
  ASSERT_FALSE(draftMax.hasError());
  ASSERT_TRUE(draftMax.value().has_value());
  EXPECT_EQ(*draftMax.value(), 6);
  auto draftExp = getIntegerParameter(
      TransportParameterId::draft_02_receive_timestamps_exponent, params);
  ASSERT_FALSE(draftExp.hasError());
  ASSERT_TRUE(draftExp.value().has_value());
  EXPECT_EQ(*draftExp.value(), 4);
}

TEST_F(TransportParametersTest, EmitsBothFormatsWhenBothEnabledAndConfigSet) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  auto& ts = clientConn.transportSettings;
  // Defaults: advertiseLegacyAckReceiveTimestamps=true.
  ts.enableIetfAckReceiveTimestamps = true;
  ts.maybeAckReceiveTimestampsConfigSentToPeer = AckReceiveTimestampsConfig{
      .maxReceiveTimestampsPerAck = 5, .receiveTimestampsExponent = 2};

  auto params = getSupportedExtTransportParams(clientConn);

  // All five dual-advertise TPs must be present with the configured values
  // (legacy enabled + legacy max + legacy exponent + draft-02 max + draft-02
  // exponent), so a partial-emission bug cannot pass.
  auto legacyEnabled = getIntegerParameter(
      TransportParameterId::ack_receive_timestamps_enabled, params);
  ASSERT_FALSE(legacyEnabled.hasError());
  ASSERT_TRUE(legacyEnabled.value().has_value());
  EXPECT_EQ(*legacyEnabled.value(), 1);

  auto legacyMax = getIntegerParameter(
      TransportParameterId::max_receive_timestamps_per_ack, params);
  ASSERT_FALSE(legacyMax.hasError());
  ASSERT_TRUE(legacyMax.value().has_value());
  EXPECT_EQ(*legacyMax.value(), 5);

  auto legacyExp = getIntegerParameter(
      TransportParameterId::receive_timestamps_exponent, params);
  ASSERT_FALSE(legacyExp.hasError());
  ASSERT_TRUE(legacyExp.value().has_value());
  EXPECT_EQ(*legacyExp.value(), 2);

  auto draftMax = getIntegerParameter(
      TransportParameterId::draft_02_max_receive_timestamps_per_ack, params);
  ASSERT_FALSE(draftMax.hasError());
  ASSERT_TRUE(draftMax.value().has_value());
  EXPECT_EQ(*draftMax.value(), 5);

  auto draftExp = getIntegerParameter(
      TransportParameterId::draft_02_receive_timestamps_exponent, params);
  ASSERT_FALSE(draftExp.hasError());
  ASSERT_TRUE(draftExp.value().has_value());
  EXPECT_EQ(*draftExp.value(), 2);
}

// Test SCONE parameter included when enabled.
TEST_F(TransportParametersTest, SconeTPIncluded) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.advertiseSconeSupport = true;

  auto customTransportParameters = getSupportedExtTransportParams(clientConn);

  int sconeCount = 0;
  for (const auto& param : customTransportParameters) {
    if (param.parameter == TransportParameterId::scone_supported) {
      sconeCount++;
    }
  }

  EXPECT_EQ(sconeCount, 1) << "scone_supported transport parameter appears "
                           << sconeCount << " times (expected exactly 1)";
}

} // namespace quic::test
