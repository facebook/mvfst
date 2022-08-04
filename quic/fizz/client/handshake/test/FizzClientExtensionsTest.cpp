/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <quic/common/test/TestUtils.h>
#include <quic/fizz/client/handshake/FizzClientExtensions.h>

#include <fizz/protocol/test/TestMessages.h>

using namespace fizz;
using namespace fizz::test;

namespace quic {
namespace test {

static EncryptedExtensions getEncryptedExtensions() {
  auto ee = TestMessages::encryptedExt();
  ServerTransportParameters serverParams;
  ee.extensions.push_back(encodeExtension(serverParams, QuicVersion::MVFST));
  return ee;
}

TEST(FizzClientHandshakeTest, TestGetChloExtensionsMvfst) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::MVFST,
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
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

TEST(FizzClientHandshakeTest, TestGetChloExtensions) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::QUIC_DRAFT,
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit,
      ConnectionId(std::vector<uint8_t>())));
  auto extensions = ext.getClientHelloExtensions();

  EXPECT_EQ(extensions.size(), 1);
  auto clientParams = getClientExtension(extensions, QuicVersion::QUIC_DRAFT);
  ASSERT_TRUE(clientParams.has_value());
  EXPECT_EQ(clientParams->parameters.size(), 11);
}

TEST(FizzClientHandshakeTest, TestGetChloExtensionsV1) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::QUIC_V1,
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
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
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
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
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
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
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
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
  ee.extensions.push_back(
      encodeExtension(serverParams, QuicVersion::QUIC_DRAFT));

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
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
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

  std::unique_ptr<CustomTransportParameter> element1 =
      std::make_unique<CustomIntegralTransportParameter>(0x4000, 12);

  std::unique_ptr<CustomTransportParameter> element2 =
      std::make_unique<CustomStringTransportParameter>(0x4001, "abc");

  std::unique_ptr<CustomTransportParameter> element3 =
      std::make_unique<CustomBlobTransportParameter>(
          0x4002, folly::IOBuf::copyBuffer(randomBytes));

  customTransportParameters.push_back(element1->encode());
  customTransportParameters.push_back(element2->encode());
  customTransportParameters.push_back(element3->encode());

  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      QuicVersion::QUIC_V1,
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
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

  auto it2 = std::find_if(
      serverParams->parameters.begin(),
      serverParams->parameters.end(),
      [](const TransportParameter& param) {
        return static_cast<uint16_t>(param.parameter) == 0x4001;
      });

  EXPECT_NE(it2, serverParams->parameters.end());

  auto it3 = std::find_if(
      serverParams->parameters.begin(),
      serverParams->parameters.end(),
      [](const TransportParameter& param) {
        return static_cast<uint16_t>(param.parameter) == 0x4002;
      });

  EXPECT_NE(it3, serverParams->parameters.end());

  // check that the values equal what we expect
  folly::IOBufEqualTo eq;

  folly::io::Cursor cursor1 = folly::io::Cursor(it1->value.get());
  auto val = decodeQuicInteger(cursor1);
  EXPECT_EQ(val->first, 12);

  EXPECT_TRUE(eq(folly::IOBuf::copyBuffer("abc"), it2->value));

  EXPECT_TRUE(eq(folly::IOBuf::copyBuffer(randomBytes), it3->value));
}
} // namespace test
} // namespace quic
