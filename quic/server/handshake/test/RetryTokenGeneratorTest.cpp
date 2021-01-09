/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/handshake/RetryTokenGenerator.h>

#include <folly/Random.h>
#include <folly/portability/GTest.h>

using namespace testing;

namespace quic::test {

class RetryTokenGeneratorTest : public Test {};

TEST_F(RetryTokenGeneratorTest, EncryptDecryptToken) {
  RetryTokenSecret secret;
  folly::Random::secureRandom(secret.data(), secret.size());

  // Encrypt the retry token using one generator
  auto connId = ConnectionId({0x14, 0x35, 0x22, 0x11});
  folly::IPAddress clientIp("109.115.3.49");
  uint16_t clientPort = 42069;

  RetryTokenGenerator tokenGenerator(secret);
  auto maybeEncryptedToken =
      tokenGenerator.encryptToken(connId, clientIp, clientPort);
  ASSERT_TRUE(maybeEncryptedToken.hasValue());

  // Decrypt the token using another generator
  RetryTokenGenerator tokenGenerator1(secret);
  auto maybeDecryptedToken =
      tokenGenerator1.decryptToken(std::move(maybeEncryptedToken.value()));
  ASSERT_TRUE(maybeDecryptedToken.hasValue());
  auto decryptedToken = maybeDecryptedToken.value();

  // Verify the token is the same
  EXPECT_EQ(decryptedToken.originalDstConnId, connId);
  EXPECT_EQ(decryptedToken.clientIp, clientIp);
  EXPECT_EQ(decryptedToken.clientPort, clientPort);

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
  EXPECT_LE(decryptedToken.timestampInMs, now);
}

} // namespace quic::test
