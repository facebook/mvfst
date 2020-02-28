/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <quic/common/test/TestUtils.h>
#include <quic/fizz/handshake/FizzTransportParameters.h>

#include <fizz/record/test/ExtensionTestsBase.h>

using namespace folly;
using namespace fizz;
using namespace fizz::test;

namespace quic {
namespace test {

StringPiece clientParams{"ffa5000a0008000400049d7f3e7d"};
StringPiece serverParams{"ffa5000a0008000400049d7f3e7d"};
StringPiece ticketParams{"ffa5000a0008000400049d7f3e7d"};

TEST_F(ExtensionsTest, TestClientParams) {
  auto exts = getExtensions(clientParams);
  auto ext = getExtension<ClientTransportParameters>(exts);
  EXPECT_EQ(ext->parameters.size(), 1);
  EXPECT_EQ(
      ext->parameters[0].parameter, TransportParameterId::initial_max_data);
  EXPECT_EQ(
      *getIntegerParameter(
          TransportParameterId::initial_max_data, ext->parameters),
      494878333ULL);
  checkEncode(std::move(*ext), clientParams);
}

TEST_F(ExtensionsTest, TestServerParams) {
  auto exts = getExtensions(serverParams);
  auto ext = getExtension<ServerTransportParameters>(exts);

  EXPECT_EQ(
      ext->parameters[0].parameter, TransportParameterId::initial_max_data);
  EXPECT_EQ(
      *getIntegerParameter(
          TransportParameterId::initial_max_data, ext->parameters),
      494878333ULL);
  checkEncode(std::move(*ext), serverParams);
}

TEST_F(ExtensionsTest, TestTicketParams) {
  auto exts = getExtensions(ticketParams);
  auto ext = getExtension<TicketTransportParameters>(exts);

  EXPECT_EQ(ext->parameters.size(), 1);
  EXPECT_EQ(
      ext->parameters[0].parameter, TransportParameterId::initial_max_data);
  EXPECT_EQ(
      *getIntegerParameter(
          TransportParameterId::initial_max_data, ext->parameters),
      494878333ULL);
  checkEncode(std::move(*ext), ticketParams);
}

} // namespace test
} // namespace quic
