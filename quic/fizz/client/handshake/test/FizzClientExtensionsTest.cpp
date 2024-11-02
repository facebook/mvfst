/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientExtensions.h>

#include <fizz/protocol/test/TestUtil.h>

using namespace fizz;
using namespace fizz::test;

namespace quic::test {

static EncryptedExtensions getEncryptedExtensions() {
  auto ee = TestMessages::encryptedExt();
  ServerTransportParameters serverParams;
  ee.extensions.push_back(encodeExtension(serverParams, QuicVersion::MVFST));
  return ee;
}

TEST(FizzClientHandshakeTest, TestGetChloExtensionsMvfst) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::MVFST,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      ConnectionId(std::vector<uint8_t>())));
  auto extensions = ext.getClientHelloExtensions();

  EXPECT_EQ(extensions.size(), 1);
  auto clientParams = getClientExtension(extensions, QuicVersion::MVFST);
  ASSERT_TRUE(clientParams.has_value());
  // Size == 10 to check that initial_source_connection_id is not included
  EXPECT_EQ(clientParams->parameters.size(), 10);
}

TEST(FizzClientHandshakeTest, TestGetChloExtensionsV1) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::QUIC_V1,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      ConnectionId(std::vector<uint8_t>())));
  auto extensions = ext.getClientHelloExtensions();

  EXPECT_EQ(extensions.size(), 1);
  auto clientParams = getClientExtension(extensions, QuicVersion::QUIC_V1);
  ASSERT_TRUE(clientParams.has_value());
  EXPECT_EQ(clientParams->parameters.size(), 11);
}

TEST(FizzClientHandshakeTest, TestGetChloExtensionsV1Alias) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::QUIC_V1_ALIAS,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      ConnectionId(std::vector<uint8_t>())));
  auto extensions = ext.getClientHelloExtensions();

  EXPECT_EQ(extensions.size(), 1);
  auto clientParams =
      getClientExtension(extensions, QuicVersion::QUIC_V1_ALIAS);
  ASSERT_TRUE(clientParams.has_value());
  EXPECT_EQ(clientParams->parameters.size(), 11);
}

TEST(FizzClientHandshakeTest, TestOnEE) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::MVFST,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      ConnectionId(std::vector<uint8_t>())));
  ext.getClientHelloExtensions();
  ext.onEncryptedExtensions(getEncryptedExtensions().extensions);
}

TEST(FizzClientHandshakeTest, TestV1RejectExtensionNumberMismatch) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::QUIC_V1,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      ConnectionId(std::vector<uint8_t>())));
  ext.getClientHelloExtensions();

  auto ee = TestMessages::encryptedExt();
  ServerTransportParameters serverParams;
  ee.extensions.push_back(encodeExtension(serverParams, QuicVersion::MVFST));

  EXPECT_THROW(ext.onEncryptedExtensions(ee.extensions), FizzException);

  auto validEE = TestMessages::encryptedExt();
  ServerTransportParameters validServerParams;
  validEE.extensions.push_back(
      encodeExtension(validServerParams, QuicVersion::QUIC_V1));

  EXPECT_NO_THROW(ext.onEncryptedExtensions(validEE.extensions));
}

TEST(FizzClientHandshakeTest, TestOnEEMissingServerParams) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::MVFST,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      ConnectionId(std::vector<uint8_t>())));
  ext.getClientHelloExtensions();
  EXPECT_THROW(
      ext.onEncryptedExtensions(TestMessages::encryptedExt().extensions),
      FizzException);
}

TEST(FizzClientHandshakeTest, TestGetChloExtensionsCustomParams) {
  std::vector<TransportParameter> customTransportParameters;

  std::string randomBytes = "\x01\x00\x55\x12\xff";

  customTransportParameters.push_back(
      encodeIntegerParameter(static_cast<TransportParameterId>(0x4000), 12));

  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::QUIC_V1,
      kDefaultConnectionFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultStreamFlowControlWindow,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      ConnectionId(std::vector<uint8_t>()),
      customTransportParameters));
  auto extensions = ext.getClientHelloExtensions();

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getClientExtension(extensions, QuicVersion::QUIC_V1);
  EXPECT_TRUE(serverParams.has_value());

  // check to see that the custom parameters are present
  auto it1 = std::find_if(
      serverParams->parameters.begin(),
      serverParams->parameters.end(),
      [](const TransportParameter& param) {
        return static_cast<uint16_t>(param.parameter) == 0x4000;
      });

  EXPECT_NE(it1, serverParams->parameters.end());

  // check that the values equal what we expect
  folly::io::Cursor cursor1 = folly::io::Cursor(it1->value.get());
  auto val = decodeQuicInteger(cursor1);
  EXPECT_EQ(val->first, 12);
}
} // namespace quic::test
