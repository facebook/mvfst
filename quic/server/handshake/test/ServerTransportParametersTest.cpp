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

namespace quic {
namespace test {

static ClientHello getClientHello() {
  auto chlo = TestMessages::clientHello();

  ClientTransportParameters clientParams;
  clientParams.parameters.emplace_back(
      CustomIntegralTransportParameter(0xffff, 0xffff).encode());

  chlo.extensions.push_back(encodeExtension(clientParams, QuicVersion::MVFST));

  return chlo;
}

TEST(ServerTransportParametersTest, TestGetExtensions) {
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
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
  auto extensions = ext.getExtensions(getClientHello());

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getServerExtension(extensions, QuicVersion::MVFST);
  EXPECT_TRUE(serverParams.has_value());
}

TEST(ServerTransportParametersTest, TestGetExtensionsMissingClientParams) {
  ServerTransportParametersExtension ext(
      QuicVersion::MVFST,
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
