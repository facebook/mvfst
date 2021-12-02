/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/handshake/RetryTokenGenerator.h>

#include <folly/Range.h>
#include <quic/codec/Decode.h>

namespace {

const std::vector<std::string> kCipherContexts = {"RetryToken"};

} // namespace

namespace quic {

RetryTokenGenerator::RetryTokenGenerator(RetryTokenSecret secret)
    : cipher_(kCipherContexts) {
  std::vector<folly::ByteRange> secrets;
  secrets.emplace_back(folly::range(secret));
  cipher_.setSecrets(secrets);
}

folly::Optional<Buf> RetryTokenGenerator::encryptToken(
    const ConnectionId& connId,
    const folly::IPAddress& clientIp,
    uint16_t clientPort) {
  // Generate the retry token in plaintext
  uint64_t timestampInMs =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch())
          .count();
  RetryToken token(connId, clientIp, clientPort, timestampInMs);
  auto plaintextToken = token.getPlaintextToken();

  // Try to encrypt it
  auto maybeEncryptedToken = cipher_.encrypt(std::move(plaintextToken));
  if (!maybeEncryptedToken) {
    LOG(ERROR) << "Failed to encypt retry token with IP " << clientIp.str()
               << " and port " << clientPort;
  }

  // If the encryption failed, this will be empty optional
  return maybeEncryptedToken;
}

folly::Optional<RetryToken> RetryTokenGenerator::decryptToken(
    Buf encryptedToken) {
  auto maybeDecryptedToken = cipher_.decrypt(std::move(encryptedToken));
  if (!maybeDecryptedToken) {
    return folly::none;
  }

  // Try to parse the decrypted token
  auto decryptedToken = (*maybeDecryptedToken).get();
  folly::io::Cursor cursor(decryptedToken);
  auto parseResult = parsePlaintextRetryToken(cursor);

  if (parseResult.hasError()) {
    LOG(ERROR) << "Failed to parse decrypted retry token";
    return folly::none;
  }
  return parseResult.value();
}

} // namespace quic
