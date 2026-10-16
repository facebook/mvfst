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
  auto connId = ConnectionId::createAndMaybeCrash({0x14, 0x35, 0x22, 0x11});
  folly::IPAddress clientIp("109.115.3.49");
  uint16_t clientPort = 42069;

  TokenGenerator tokenGenerator(secret);
  RetryToken token(connId, clientIp, clientPort);
  auto maybeEncryptedToken = tokenGenerator.encryptToken(token);
  ASSERT_TRUE(maybeEncryptedToken.has_value());

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

TEST_F(RetryTokenGeneratorTest, DecryptRetryTokenWithoutServerChosenSrcConnId) {
  TokenSecret secret;
  folly::Random::secureRandom(secret.data(), secret.size());
  auto connId = ConnectionId::createAndMaybeCrash(
      {0x14, 0x35, 0x22, 0x11, 0x63, 0x51, 0x08, 0x9a});
  folly::IPAddress clientIp("109.115.3.49");

  TokenGenerator tokenGenerator(secret);
  RetryToken token(connId, clientIp, 42069);
  auto maybeEncryptedToken = tokenGenerator.encryptToken(token);
  ASSERT_TRUE(maybeEncryptedToken.has_value());

  TokenGenerator tokenGenerator1(secret);
  auto decryptedToken = tokenGenerator1.decryptRetryToken(
      std::move(maybeEncryptedToken.value()), connId, clientIp);
  ASSERT_TRUE(decryptedToken.has_value());
  EXPECT_EQ(decryptedToken->originalDstConnId, connId);
  EXPECT_FALSE(decryptedToken->retrySrcConnId.has_value());
  EXPECT_EQ(decryptedToken->timestampInMs, token.timestampInMs);
}

TEST_F(
    RetryTokenGeneratorTest,
    EncryptDecryptRetryTokenWithServerChosenSrcConnId) {
  TokenSecret secret;
  folly::Random::secureRandom(secret.data(), secret.size());
  auto originalDstConnId = ConnectionId::createAndMaybeCrash(
      {0x14, 0x35, 0x22, 0x11, 0x63, 0x51, 0x08, 0x9a});
  auto retrySrcConnId = ConnectionId::createAndMaybeCrash(
      {0x40, 0x00, 0x07, 0xd6, 0xa1, 0x89, 0x50, 0x41});
  folly::IPAddress clientIp("109.115.3.49");

  TokenGenerator tokenGenerator(secret);
  RetryToken token(originalDstConnId, clientIp, 42069);
  token.retrySrcConnId = retrySrcConnId;
  auto maybeEncryptedToken = tokenGenerator.encryptToken(token);
  ASSERT_TRUE(maybeEncryptedToken.has_value());
  auto encryptedToken = maybeEncryptedToken.value()->toString();

  // The client sends its next Initial to the Retry source connection id.
  TokenGenerator tokenGenerator1(secret);
  auto decryptedToken = tokenGenerator1.decryptRetryToken(
      folly::IOBuf::copyBuffer(encryptedToken), retrySrcConnId, clientIp);
  ASSERT_TRUE(decryptedToken.has_value());
  EXPECT_EQ(decryptedToken->originalDstConnId, originalDstConnId);
  EXPECT_EQ(decryptedToken->retrySrcConnId, retrySrcConnId);
  EXPECT_EQ(decryptedToken->timestampInMs, token.timestampInMs);

  EXPECT_FALSE(tokenGenerator1
                   .decryptRetryToken(
                       folly::IOBuf::copyBuffer(encryptedToken),
                       originalDstConnId,
                       clientIp)
                   .has_value());
  EXPECT_FALSE(tokenGenerator1
                   .decryptRetryToken(
                       folly::IOBuf::copyBuffer(encryptedToken),
                       retrySrcConnId,
                       folly::IPAddress("109.115.3.50"))
                   .has_value());
}

TEST_F(RetryTokenGeneratorTest, EncryptDecryptNewToken) {
  TokenSecret secret;
  folly::Random::secureRandom(secret.data(), secret.size());

  // Encrypt the new token using one generator
  folly::IPAddress clientIp("109.115.3.49");

  TokenGenerator tokenGenerator(secret);
  NewToken token(clientIp);
  auto maybeEncryptedToken = tokenGenerator.encryptToken(token);
  ASSERT_TRUE(maybeEncryptedToken.has_value());

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
