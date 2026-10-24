/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/handshake/ContiguousAead.h>

#include <fizz/crypto/aead/CryptoUtil.h>
#include <quic/common/MvfstLogging.h>

namespace quic {

namespace {

std::span<const uint8_t> associatedDataSpan(const Buf* associatedData) {
  MVCHECK(associatedData == nullptr || !associatedData->isChained());
  if (!associatedData) {
    return {};
  }
  return {associatedData->data(), associatedData->length()};
}

} // namespace

bool ContiguousAead::isAes128GcmKey(const fizz::TrafficKey& key) {
  return key.key && key.iv && key.key->computeChainDataLength() == kKeyLength &&
      key.iv->computeChainDataLength() == kNonceLength;
}

ContiguousAead::ContiguousAead(fizz::TrafficKey key) : key_(std::move(key)) {
  MVCHECK(isAes128GcmKey(key_));
  key_.key->coalesce();
  key_.iv->coalesce();
}

Optional<TrafficKey> ContiguousAead::getKey() const {
  TrafficKey quicKey;
  quicKey.key = key_.key->clone();
  quicKey.iv = key_.iv->clone();
  return quicKey;
}

std::array<uint8_t, ContiguousAead::kNonceLength> ContiguousAead::makeNonce(
    uint64_t seqNum) const {
  return fizz::createIV<kNonceLength>(
      seqNum,
      key_.iv->length(),
      folly::ByteRange(key_.iv->data(), key_.iv->length()));
}

quic::Expected<BufPtr, QuicError> ContiguousAead::inplaceEncrypt(
    BufPtr&& plaintext,
    const Buf* associatedData,
    uint64_t seqNum) const {
  const auto aad = associatedDataSpan(associatedData);
  if (plaintext->prev()->tailroom() < kTagLength) {
    plaintext->appendToChain(folly::IOBuf::create(kTagLength));
  }
  plaintext->coalesce();

  const auto nonce = makeNonce(seqNum);
  uint8_t* const data = plaintext->writableData();
  const size_t length = plaintext->length();
  if (!seal(
          nonce,
          aad,
          {data, length},
          {data, length},
          {data + length, kTagLength})) {
    return quic::make_unexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, "encryption failed"));
  }
  plaintext->append(kTagLength);
  return std::move(plaintext);
}

Optional<BufPtr> ContiguousAead::tryDecrypt(
    BufPtr&& ciphertext,
    const Buf* associatedData,
    uint64_t seqNum) const {
  const auto aad = associatedDataSpan(associatedData);
  ciphertext->coalesce();
  if (ciphertext->length() < kTagLength) {
    return std::nullopt;
  }
  const size_t plaintextLength = ciphertext->length() - kTagLength;

  const auto nonce = makeNonce(seqNum);
  uint8_t* const data = ciphertext->writableData();
  if (!open(
          nonce,
          aad,
          {data, plaintextLength},
          {data + plaintextLength, kTagLength},
          {data, plaintextLength})) {
    return std::nullopt;
  }
  ciphertext->trimEnd(kTagLength);
  return std::move(ciphertext);
}

} // namespace quic
