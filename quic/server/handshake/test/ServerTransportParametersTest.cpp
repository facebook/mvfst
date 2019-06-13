/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/QuicConstants.h>
#include <quic/common/test/TestUtils.h>
#include <quic/server/handshake/ServerTransportParametersExtension.h>

#include <fizz/protocol/test/TestMessages.h>

using namespace fizz;
using namespace fizz::test;
using namespace quic;

namespace quic {
namespace test {

static ClientHello getClientHello(folly::Optional<QuicVersion> initialVersion) {
  auto chlo = TestMessages::clientHello();

  ClientTransportParameters clientParams;
  clientParams.initial_version = initialVersion;
  clientParams.parameters.emplace_back(
      CustomIntegralTransportParameter(0xffff, 0xffff).encode());

  chlo.extensions.push_back(encodeExtension(std::move(clientParams)));

  return chlo;
}

TEST(ServerTransportParametersTest, TestGetExtensions) {
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      {MVFST1, QuicVersion::MVFST},
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultPartialReliability,
      generateStatelessResetToken());
  auto extensions = ext.getExtensions(getClientHello(folly::none));

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getExtension<ServerTransportParameters>(extensions);
  EXPECT_TRUE(serverParams.hasValue());
  EXPECT_FALSE(serverParams->negotiated_version.hasValue());
}

TEST(ServerTransportParametersTest, TestGetExtensionsD18) {
  StatelessResetToken token = generateStatelessResetToken();
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      {MVFST1, QuicVersion::MVFST},
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultPartialReliability,
      token);
  auto extensions = ext.getExtensions(getClientHello(QuicVersion::MVFST));

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getExtension<ServerTransportParameters>(extensions);
  EXPECT_TRUE(serverParams.hasValue());
  EXPECT_TRUE(serverParams->negotiated_version.hasValue());

  folly::Optional<StatelessResetToken> tokWrapper =
      getStatelessResetTokenParameter(serverParams->parameters);

  StatelessResetToken expectedToken;
  EXPECT_NO_THROW(expectedToken = *tokWrapper);
  EXPECT_EQ(token, expectedToken);
}

TEST(ServerTransportParametersTest, TestGetExtensionsMissingClientParams) {
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      {MVFST1, QuicVersion::MVFST},
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultPartialReliability,
      generateStatelessResetToken());
  EXPECT_THROW(ext.getExtensions(TestMessages::clientHello()), FizzException);
}
} // namespace test
} // namespace quic
