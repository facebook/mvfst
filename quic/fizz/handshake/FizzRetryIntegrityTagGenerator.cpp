// Copyright 2004-present Facebook. All Rights Reserved.

#include <quic/fizz/handshake/FizzRetryIntegrityTagGenerator.h>

#include <fizz/crypto/aead/AESGCM128.h>
#include <fizz/crypto/aead/Aead.h>
#include <fizz/crypto/aead/OpenSSLEVPCipher.h>

namespace quic {

// These are the values as per version 29 of the QUIC-TLS draft
constexpr folly::StringPiece retryPacketKey =
    "\xcc\xce\x18\x7e\xd0\x9a\x09\xd0\x57\x28\x15\x5a\x6c\xb9\x6b\xe1";
constexpr folly::StringPiece retryPacketNonce =
    "\xe5\x49\x30\xf9\x7f\x21\x36\xf0\x53\x0a\x8c\x1c";

std::unique_ptr<folly::IOBuf>
FizzRetryIntegrityTagGenerator::getRetryIntegrityTag(
    const folly::IOBuf* pseudoRetryPacket) {
  std::unique_ptr<fizz::Aead> retryCipher =
      fizz::OpenSSLEVPCipher::makeCipher<fizz::AESGCM128>();
  fizz::TrafficKey trafficKey;
  trafficKey.key = folly::IOBuf::copyBuffer(retryPacketKey);
  trafficKey.iv = folly::IOBuf::copyBuffer(retryPacketNonce);
  retryCipher->setKey(std::move(trafficKey));

  return retryCipher->encrypt(
      std::make_unique<folly::IOBuf>(), pseudoRetryPacket, 0);
}

} // namespace quic
