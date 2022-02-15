/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/io/IOBuf.h>
#include <quic/server/handshake/TokenGenerator.h>

#include <folly/Range.h>
#include <quic/codec/Decode.h>

namespace {

const std::vector<std::string> kCipherContexts = {"RetryToken_V2"};

} // namespace

namespace quic {

TokenGenerator::TokenGenerator(TokenSecret secret) : cipher_(kCipherContexts) {
  std::vector<folly::ByteRange> secrets;
  secrets.emplace_back(folly::range(secret));
  cipher_.setSecrets(secrets);
}

folly::Optional<Buf> TokenGenerator::encryptToken(
    const QuicAddrValidationToken& token) {
  // Generate the retry token in plaintext
  auto plainTextToken = token.getPlaintextToken();

  // Try to encrypt it
  auto maybeEncryptedToken = cipher_.encrypt(
      std::move(plainTextToken), token.genAeadAssocData().get());
  if (!maybeEncryptedToken) {
    LOG(ERROR) << "Failed to encypt addr validation token with IP "
               << token.clientIp.str();
  }

  // If the encryption failed, this will be empty optional
  return maybeEncryptedToken;
}

uint64_t TokenGenerator::decryptToken(Buf encryptedToken, Buf aeadAssocData) {
  auto maybeDecryptedToken =
      cipher_.decrypt(std::move(encryptedToken), aeadAssocData.get());

  if (!maybeDecryptedToken) {
    return 0;
  }

  // Try to parse the decrypted token
  auto decryptedToken = (*maybeDecryptedToken).get();
  folly::io::Cursor cursor(decryptedToken);

  auto parseResult = parsePlaintextRetryOrNewToken(cursor);

  if (parseResult.hasError()) {
    LOG(ERROR) << "Failed to parse decrypted retry token";
    return 0;
  }

  return parseResult.value();
}

} // namespace quic
