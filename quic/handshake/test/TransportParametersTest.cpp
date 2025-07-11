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
    if (conn.transportSettings.supportDirectEncap) {
      params.push_back(
          encodeEmptyParameter(TransportParameterId::client_direct_encap));
    }
    return params;
  }
};

// Test client-side direct encap parameter generation
TEST_F(TransportParametersTest, ClientDirectEncapEnabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.supportDirectEncap = true;

  auto customTransportParams = getClientTransportParams(clientConn);

  auto it = findParameter(
      customTransportParams, TransportParameterId::client_direct_encap);
  EXPECT_TRUE(it != customTransportParams.end());
  EXPECT_TRUE(it->value->empty());
}

TEST_F(TransportParametersTest, ClientDirectEncapDisabled) {
  QuicClientConnectionState clientConn(
      FizzClientQuicHandshakeContext::Builder().build());
  clientConn.transportSettings.supportDirectEncap = false;

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
  serverConn.transportSettings.directEncapAddress =
      folly::IPAddress("192.168.1.1");

  // Create client parameters containing client_direct_encap
  std::vector<TransportParameter> clientParams;
  clientParams.push_back(
      encodeEmptyParameter(TransportParameterId::client_direct_encap));

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
  serverConn.transportSettings.directEncapAddress =
      folly::IPAddress("2001:db8::1");

  // Create client parameters containing client_direct_encap
  std::vector<TransportParameter> clientParams;
  clientParams.push_back(
      encodeEmptyParameter(TransportParameterId::client_direct_encap));

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

// Test server doesn't send server_direct_encap when address not configured
TEST_F(TransportParametersTest, ServerDirectEncapNoAddress) {
  QuicServerConnectionState serverConn(
      FizzServerQuicHandshakeContext::Builder().build());
  // Don't set directEncapAddress

  // Create client parameters containing client_direct_encap
  std::vector<TransportParameter> clientParams;
  clientParams.push_back(
      encodeEmptyParameter(TransportParameterId::client_direct_encap));

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
  serverConn.transportSettings.directEncapAddress =
      folly::IPAddress("192.168.1.1");

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

} // namespace quic::test
