/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/handshake/StatelessResetGenerator.h>

#include <folly/Random.h>
#include <folly/SocketAddress.h>
#include <folly/portability/GTest.h>

using namespace testing;

namespace quic {
namespace test {

class StatelessResetGeneratorTest : public Test {};

TEST_F(StatelessResetGeneratorTest, SameSecretSameAddress) {
  StatelessResetSecret secret;
  folly::Random::secureRandom(secret.data(), secret.size());
  folly::SocketAddress address("1.2.3.4", 8080);
  StatelessResetGenerator generator1(secret, address.getFullyQualified()),
      generator2(secret, address.getFullyQualified());
  EXPECT_EQ(
      generator1.generateToken(ConnectionId({0x14, 0x35, 0x22, 0x11})),
      generator2.generateToken(ConnectionId({0x14, 0x35, 0x22, 0x11})));
}

TEST_F(StatelessResetGeneratorTest, SameSecretDifferentAddress) {
  StatelessResetSecret secret;
  folly::Random::secureRandom(secret.data(), secret.size());
  folly::SocketAddress address1("1.2.3.4", 8080), address2("2.3.4.5", 8888);
  StatelessResetGenerator generator1(secret, address1.getFullyQualified()),
      generator2(secret, address2.getFullyQualified());
  // I was told by security expert that by the time they collide, I'm already
  // fired.
  EXPECT_NE(
      generator1.generateToken(ConnectionId({0x14, 0x35, 0x22, 0x11})),
      generator2.generateToken(ConnectionId({0x14, 0x35, 0x22, 0x11})));
}

TEST_F(StatelessResetGeneratorTest, DifferentSecretSameAddress) {
  // Same here, it will collide some day, but i'd be gone.
  StatelessResetSecret secret1, secret2;
  folly::Random::secureRandom(secret1.data(), secret1.size());
  folly::Random::secureRandom(secret2.data(), secret2.size());
  folly::SocketAddress address("2.3.4.255", 8088);
  StatelessResetGenerator generator1(secret1, address.getFullyQualified()),
      generator2(secret2, address.getFullyQualified());
  EXPECT_NE(
      generator1.generateToken(ConnectionId({0x14, 0x35, 0x22, 0x11})),
      generator2.generateToken(ConnectionId({0x14, 0x35, 0x22, 0x11})));
}

} // namespace test
} // namespace quic
