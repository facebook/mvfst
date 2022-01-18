/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <algorithm>

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

static ClientHello getClientHello(QuicVersion version) {
  auto chlo = TestMessages::clientHello();

  ClientTransportParameters clientParams;
  clientParams.parameters.emplace_back(
      CustomIntegralTransportParameter(0xffff, 0xffff).encode());

  chlo.extensions.push_back(encodeExtension(clientParams, version));

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
      generateStatelessResetToken(),
      ConnectionId(std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId(std::vector<uint8_t>()));
  auto extensions = ext.getExtensions(getClientHello(QuicVersion::MVFST));

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
      generateStatelessResetToken(),
      ConnectionId(std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId(std::vector<uint8_t>()));
  EXPECT_THROW(ext.getExtensions(TestMessages::clientHello()), FizzException);
}
TEST(ServerTransportParametersTest, TestQuicV1RejectDraftExtensionNumber) {
  ServerTransportParametersExtension ext(
      QuicVersion::QUIC_V1,
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      generateStatelessResetToken(),
      ConnectionId(std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId(std::vector<uint8_t>()));
  EXPECT_THROW(
      ext.getExtensions(getClientHello(QuicVersion::QUIC_DRAFT)),
      FizzException);
  EXPECT_NO_THROW(ext.getExtensions(getClientHello(QuicVersion::QUIC_V1)));
}

TEST(ServerTransportParametersTest, TestQuicV1RejectDuplicateExtensions) {
  ServerTransportParametersExtension ext(
      QuicVersion::QUIC_V1,
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      generateStatelessResetToken(),
      ConnectionId(std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId(std::vector<uint8_t>()));

  auto chlo = getClientHello(QuicVersion::QUIC_V1);
  ClientTransportParameters duplicateClientParams;
  duplicateClientParams.parameters.emplace_back(
      CustomIntegralTransportParameter(0xffff, 0xffff).encode());
  chlo.extensions.push_back(
      encodeExtension(duplicateClientParams, QuicVersion::QUIC_V1));

  EXPECT_THROW(ext.getExtensions(chlo), FizzException);
}
TEST(ServerTransportParametersTest, TestQuicV1Fields) {
  ServerTransportParametersExtension ext(
      QuicVersion::QUIC_V1,
      kDefaultConnectionWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      kDefaultStreamWindowSize,
      std::numeric_limits<uint32_t>::max(),
      std::numeric_limits<uint32_t>::max(),
      kDefaultIdleTimeout,
      kDefaultAckDelayExponent,
      kDefaultUDPSendPacketLen,
      generateStatelessResetToken(),
      ConnectionId(std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId(std::vector<uint8_t>{0xfb, 0xfa, 0xf9, 0xf8}));
  auto extensions = ext.getExtensions(getClientHello(QuicVersion::QUIC_V1));

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getServerExtension(extensions, QuicVersion::QUIC_V1);
  EXPECT_TRUE(serverParams.has_value());
  auto quicTransportParams = serverParams.value().parameters;
  auto hasInitialSourceCid = std::any_of(
      quicTransportParams.cbegin(),
      quicTransportParams.cend(),
      [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::initial_source_connection_id;
      });
  EXPECT_TRUE(hasInitialSourceCid);
  auto hasOriginalDestCid = std::any_of(
      quicTransportParams.cbegin(),
      quicTransportParams.cend(),
      [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::original_destination_connection_id;
      });
  EXPECT_TRUE(hasOriginalDestCid);
}

TEST(ServerTransportParametersTest, TestMvfstFields) {
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
      generateStatelessResetToken(),
      ConnectionId(std::vector<uint8_t>{0xff, 0xfe, 0xfd, 0xfc}),
      ConnectionId(std::vector<uint8_t>{0xfb, 0xfa, 0xf9, 0xf8}));
  auto extensions = ext.getExtensions(getClientHello(QuicVersion::MVFST));

  EXPECT_EQ(extensions.size(), 1);
  auto serverParams = getServerExtension(extensions, QuicVersion::MVFST);
  EXPECT_TRUE(serverParams.has_value());
  auto quicTransportParams = serverParams.value().parameters;
  auto hasInitialSourceCid = std::any_of(
      quicTransportParams.cbegin(),
      quicTransportParams.cend(),
      [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::initial_source_connection_id;
      });
  EXPECT_FALSE(hasInitialSourceCid);
  auto hasOriginalDestCid = std::any_of(
      quicTransportParams.cbegin(),
      quicTransportParams.cend(),
      [](const TransportParameter& p) {
        return p.parameter ==
            TransportParameterId::original_destination_connection_id;
      });
  EXPECT_FALSE(hasOriginalDestCid);
}

} // namespace test
} // namespace quic
