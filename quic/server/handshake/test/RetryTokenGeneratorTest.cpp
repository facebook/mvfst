/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/handshake/TokenGenerator.h>

#include <folly/Random.h>
#include <folly/portability/GTest.h>

using namespace testing;

namespace quic::test {

class RetryTokenGeneratorTest : public Test {};

TEST_F(RetryTokenGeneratorTest, EncryptDecryptRetryToken) {
  TokenSecret secret;
  folly::Random::secureRandom(secret.data(), secret.size());

  // Encrypt the retry token using one generator
  auto connId = ConnectionId({0x14, 0x35, 0x22, 0x11});
  folly::IPAddress clientIp("109.115.3.49");
  uint16_t clientPort = 42069;

  TokenGenerator tokenGenerator(secret);
  RetryToken token(connId, clientIp, clientPort);
  auto maybeEncryptedToken = tokenGenerator.encryptToken(token);
  ASSERT_TRUE(maybeEncryptedToken.hasValue());

  // Decrypt the token using another generator
  TokenGenerator tokenGenerator1(secret);
  auto maybeDecryptedTokenMs = tokenGenerator1.decryptToken(
      std::move(maybeEncryptedToken.value()), token.genAeadAssocData());
  ASSERT_TRUE(maybeDecryptedTokenMs);

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
  EXPECT_LE(maybeDecryptedTokenMs, now);
}

TEST_F(RetryTokenGeneratorTest, EncryptDecryptNewToken) {
  TokenSecret secret;
  folly::Random::secureRandom(secret.data(), secret.size());

  // Encrypt the new token using one generator
  folly::IPAddress clientIp("109.115.3.49");

  TokenGenerator tokenGenerator(secret);
  NewToken token(clientIp);
  auto maybeEncryptedToken = tokenGenerator.encryptToken(token);
  ASSERT_TRUE(maybeEncryptedToken.hasValue());

  // Decrypt the token using another generator
  TokenGenerator tokenGenerator1(secret);
  auto maybeDecryptedTokenMs = tokenGenerator1.decryptToken(
      std::move(maybeEncryptedToken.value()), token.genAeadAssocData());
  ASSERT_TRUE(maybeDecryptedTokenMs);

  uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::system_clock::now().time_since_epoch())
                     .count();
  EXPECT_LE(maybeDecryptedTokenMs, now);
}

} // namespace quic::test
