/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gtest/gtest.h>

#include <quic/client/handshake/FizzClientExtensions.h>
#include <quic/common/test/TestUtils.h>

#include <fizz/protocol/test/TestMessages.h>

using namespace fizz;
using namespace fizz::test;

namespace quic {
namespace test {

static EncryptedExtensions getEncryptedExtensions() {
  auto ee = TestMessages::encryptedExt();
  ServerTransportParameters serverParams;
  ee.extensions.push_back(encodeExtension(std::move(serverParams)));
  return ee;
}

TEST(FizzClientHandshakeTest, TestGetChloExtensions) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit));
  auto extensions = ext.getClientHelloExtensions();

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getExtension<ClientTransportParameters>(extensions);
  EXPECT_TRUE(serverParams.has_value());
}

TEST(FizzClientHandshakeTest, TestOnEE) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit));
  ext.getClientHelloExtensions();
  ext.onEncryptedExtensions(getEncryptedExtensions().extensions);
}

TEST(FizzClientHandshakeTest, TestOnEEMissingServerParams) {
  FizzClientExtensions ext(std::make_shared<ClientTransportParametersExtension>(
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultMaxStreamsBidirectional,
      kDefaultMaxStreamsUnidirectional,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultActiveConnectionIdLimit));
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
      customTransportParameters));
  auto extensions = ext.getClientHelloExtensions();

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getExtension<ClientTransportParameters>(extensions);
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
