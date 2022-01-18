/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/handshake/FizzRetryIntegrityTagGenerator.h>

#include <fizz/crypto/aead/AESGCM128.h>
#include <fizz/crypto/aead/Aead.h>
#include <fizz/crypto/aead/OpenSSLEVPCipher.h>

namespace quic {

// These are the values as per draft 29 and v1 of the QUIC-TLS draft
static const folly::StringPiece retryPacketKey(QuicVersion version) {
  if (version == QuicVersion::QUIC_V1) {
    return "\xbe\x0c\x69\x0b\x9f\x66\x57\x5a\x1d\x76\x6b\x54\xe3\x68\xc8\x4e";
  } else {
    return "\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1";
  }
}

// These are the values as per draft 29 and v1 of the QUIC-TLS draft
static const folly::StringPiece retryPacketNonce(QuicVersion version) {
  if (version == QuicVersion::QUIC_V1) {
    return "\x46\x15\x99\xd3\x5d\x63\x2b\xf2\x23\x98\x25\xbb";
  } else {
    return "\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c";
  }
}

std::unique_ptr<folly::IOBuf>
FizzRetryIntegrityTagGenerator::getRetryIntegrityTag(
    QuicVersion version,
    const folly::IOBuf* pseudoRetryPacket) {
  std::unique_ptr<fizz::Aead> retryCipher =
      fizz::OpenSSLEVPCipher::makeCipher<fizz::AESGCM128>();
  fizz::TrafficKey trafficKey;
  trafficKey.key = folly::IOBuf::copyBuffer(retryPacketKey(version));
  trafficKey.iv = folly::IOBuf::copyBuffer(retryPacketNonce(version));
  retryCipher->setKey(std::move(trafficKey));

  return retryCipher->encrypt(
      std::make_unique<folly::IOBuf>(), pseudoRetryPacket, 0);
}

} // namespace quic
