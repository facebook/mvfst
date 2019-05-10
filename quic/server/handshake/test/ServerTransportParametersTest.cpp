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
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultPartialReliability);
  auto extensions = ext.getExtensions(getClientHello(folly::none));

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getExtension<ServerTransportParameters>(extensions);
  EXPECT_TRUE(serverParams.hasValue());
  EXPECT_FALSE(serverParams->negotiated_version.hasValue());
}

TEST(ServerTransportParametersTest, TestGetExtensionsD18) {
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      {MVFST1, QuicVersion::MVFST},
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultPartialReliability);
  auto extensions = ext.getExtensions(getClientHello(QuicVersion::MVFST));

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getExtension<ServerTransportParameters>(extensions);
  EXPECT_TRUE(serverParams.hasValue());
  EXPECT_TRUE(serverParams->negotiated_version.hasValue());
}

TEST(ServerTransportParametersTest, TestGetExtensionsMissingClientParams) {
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
      {MVFST1, QuicVersion::MVFST},
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      kDefaultPartialReliability);
  EXPECT_THROW(ext.getExtensions(TestMessages::clientHello()), FizzException);
}
}
}
