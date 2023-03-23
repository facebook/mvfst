/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <fizz/record/test/ExtensionTestsBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/handshake/FizzTransportParameters.h>

using namespace fizz;
using namespace folly;

namespace quic {
namespace test {

class QuicExtensionsTest : public testing::Test {
 protected:
  Buf getBuf(folly::StringPiece hex) {
    auto data = unhexlify(hex);
    return folly::IOBuf::copyBuffer(data.data(), data.size());
  }

  std::vector<Extension> getExtensions(folly::StringPiece hex) {
    auto buf = QuicExtensionsTest::getBuf(hex);
    folly::io::Cursor cursor(buf.get());
    Extension ext;
    EXPECT_EQ(fizz::detail::read(ext, cursor), buf->computeChainDataLength());
    EXPECT_TRUE(cursor.isAtEnd());
    std::vector<Extension> exts;
    exts.push_back(std::move(ext));
    return exts;
  }

  template <class T>
  void checkEncode(
      T&& ext,
      folly::StringPiece expectedHex,
      QuicVersion encodingVersion) {
    auto encoded = encodeExtension(std::forward<T>(ext), encodingVersion);
    auto buf = folly::IOBuf::create(0);
    folly::io::Appender appender(buf.get(), 10);
    fizz::detail::write(encoded, appender);
    EXPECT_TRUE(folly::IOBufEqualTo()(buf, getBuf(expectedHex)));
  }
};

StringPiece clientParamsV1{"0039000604049d7f3e7d"};
StringPiece clientParamsD29{"ffa5000604049d7f3e7d"};
StringPiece serverParamsV1{"003900100008121254761256146904049d7f3e7d"};
StringPiece serverParamsD29{"ffa500100008121254761256146904049d7f3e7d"};
StringPiece ticketParamsV1{"0039000604049d7f3e7d"};
StringPiece ticketParamsD29{"ffa5000604049d7f3e7d"};

TEST_F(QuicExtensionsTest, TestClientParamsV1) {
  auto exts = getExtensions(clientParamsV1);
  auto ext = getClientExtension(exts, QuicVersion::QUIC_V1);
  EXPECT_EQ(ext->parameters.size(), 1);
  EXPECT_EQ(
      ext->parameters[0].parameter, TransportParameterId::initial_max_data);
  EXPECT_EQ(
      *getIntegerParameter(
          TransportParameterId::initial_max_data, ext->parameters),
      494878333ULL);
  checkEncode(std::move(*ext), clientParamsV1, QuicVersion::QUIC_V1);

  // Confirm D29 parameters are not parsed for V1.
  auto d29Exts = getExtensions(clientParamsD29);
  auto d2Ext = getClientExtension(exts, QuicVersion::QUIC_DRAFT);
  EXPECT_EQ(d2Ext, folly::none);
}

TEST_F(QuicExtensionsTest, TestClientParamsD29) {
  auto exts = getExtensions(clientParamsD29);
  auto ext = getClientExtension(exts, QuicVersion::QUIC_DRAFT);
  EXPECT_EQ(ext->parameters.size(), 1);
  EXPECT_EQ(
      ext->parameters[0].parameter, TransportParameterId::initial_max_data);
  EXPECT_EQ(
      *getIntegerParameter(
          TransportParameterId::initial_max_data, ext->parameters),
      494878333ULL);
  checkEncode(std::move(*ext), clientParamsD29, QuicVersion::QUIC_DRAFT);
}

TEST_F(QuicExtensionsTest, TestServerParamsV1) {
  auto exts = getExtensions(serverParamsV1);
  auto ext = getServerExtension(exts, QuicVersion::QUIC_V1);

  EXPECT_EQ(
      ext->parameters[0].parameter,
      TransportParameterId::original_destination_connection_id);
  EXPECT_EQ(
      ext->parameters[1].parameter, TransportParameterId::initial_max_data);
  EXPECT_EQ(
      *getIntegerParameter(
          TransportParameterId::initial_max_data, ext->parameters),
      494878333ULL);
  ConnectionId connId(
      {'\x12', '\x12', '\x54', '\x76', '\x12', '\x56', '\x14', '\x69'});
  EXPECT_EQ(
      *getConnIdParameter(
          TransportParameterId::original_destination_connection_id,
          ext->parameters),
      connId);
  checkEncode(std::move(*ext), serverParamsV1, QuicVersion::QUIC_V1);

  // Confirm D29 parameters are not parsed for V1.
  auto d29Exts = getExtensions(serverParamsD29);
  auto d2Ext = getServerExtension(exts, QuicVersion::QUIC_DRAFT);
  EXPECT_EQ(d2Ext, folly::none);
}

TEST_F(QuicExtensionsTest, TestServerParamsD29) {
  auto exts = getExtensions(serverParamsD29);
  auto ext = getServerExtension(exts, QuicVersion::QUIC_DRAFT);

  EXPECT_EQ(
      ext->parameters[0].parameter,
      TransportParameterId::original_destination_connection_id);
  EXPECT_EQ(
      ext->parameters[1].parameter, TransportParameterId::initial_max_data);
  EXPECT_EQ(
      *getIntegerParameter(
          TransportParameterId::initial_max_data, ext->parameters),
      494878333ULL);
  ConnectionId connId(
      {'\x12', '\x12', '\x54', '\x76', '\x12', '\x56', '\x14', '\x69'});
  EXPECT_EQ(
      *getConnIdParameter(
          TransportParameterId::original_destination_connection_id,
          ext->parameters),
      connId);
  checkEncode(std::move(*ext), serverParamsD29, QuicVersion::QUIC_DRAFT);
}

TEST_F(QuicExtensionsTest, TestTicketParamsV1) {
  auto exts = getExtensions(ticketParamsV1);
  auto ext = getTicketExtension(exts, QuicVersion::QUIC_V1);

  EXPECT_EQ(ext->parameters.size(), 1);
  EXPECT_EQ(
      ext->parameters[0].parameter, TransportParameterId::initial_max_data);
  EXPECT_EQ(
      *getIntegerParameter(
          TransportParameterId::initial_max_data, ext->parameters),
      494878333ULL);
  checkEncode(std::move(*ext), ticketParamsV1, QuicVersion::QUIC_V1);

  // Confirm D29 parameters are not parsed for V1.
  auto d29Exts = getExtensions(ticketParamsD29);
  auto d2Ext = getTicketExtension(exts, QuicVersion::QUIC_DRAFT);
  EXPECT_EQ(d2Ext, folly::none);
}

TEST_F(QuicExtensionsTest, TestTicketParamsD29) {
  auto exts = getExtensions(ticketParamsD29);
  auto ext = getTicketExtension(exts, QuicVersion::QUIC_DRAFT);

  EXPECT_EQ(ext->parameters.size(), 1);
  EXPECT_EQ(
      ext->parameters[0].parameter, TransportParameterId::initial_max_data);
  EXPECT_EQ(
      *getIntegerParameter(
          TransportParameterId::initial_max_data, ext->parameters),
      494878333ULL);
  checkEncode(std::move(*ext), ticketParamsD29, QuicVersion::QUIC_DRAFT);
}

} // namespace test
} // namespace quic
