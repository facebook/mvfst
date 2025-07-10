/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/handshake/FizzPacketNumberCipher.h>

namespace quic {

static quic::Expected<void, QuicError> setKeyImpl(
    folly::ssl::EvpCipherCtxUniquePtr& context,
    const EVP_CIPHER* cipher,
    ByteRange key) {
  DCHECK_EQ(key.size(), EVP_CIPHER_key_length(cipher));
  context.reset(EVP_CIPHER_CTX_new());
  if (context == nullptr) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR,
        "Unable to allocate an EVP_CIPHER_CTX object"));
  }
  if (EVP_EncryptInit_ex(context.get(), cipher, nullptr, key.data(), nullptr) !=
      1) {
    return quic::make_unexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, "Init error"));
  }
  return {};
}

static quic::Expected<HeaderProtectionMask, QuicError> maskImpl(
    const folly::ssl::EvpCipherCtxUniquePtr& context,
    ByteRange sample) {
  HeaderProtectionMask outMask;
  CHECK_EQ(sample.size(), outMask.size());
  int outLen = 0;
  if (EVP_EncryptUpdate(
          context.get(),
          outMask.data(),
          &outLen,
          sample.data(),
          static_cast<int>(sample.size())) != 1 ||
      static_cast<HeaderProtectionMask::size_type>(outLen) != outMask.size()) {
    return quic::make_unexpected(
        QuicError(TransportErrorCode::INTERNAL_ERROR, "Encryption error"));
  }
  return outMask;
}

quic::Expected<void, QuicError> Aes128PacketNumberCipher::setKey(
    ByteRange key) {
  pnKey_ = BufHelpers::copyBuffer(key);
  return setKeyImpl(encryptCtx_, EVP_aes_128_ecb(), key);
}

quic::Expected<void, QuicError> Aes256PacketNumberCipher::setKey(
    ByteRange key) {
  pnKey_ = BufHelpers::copyBuffer(key);
  return setKeyImpl(encryptCtx_, EVP_aes_256_ecb(), key);
}

const BufPtr& Aes128PacketNumberCipher::getKey() const {
  return pnKey_;
}

const BufPtr& Aes256PacketNumberCipher::getKey() const {
  return pnKey_;
}

quic::Expected<HeaderProtectionMask, QuicError> Aes128PacketNumberCipher::mask(
    ByteRange sample) const {
  return maskImpl(encryptCtx_, sample);
}

quic::Expected<HeaderProtectionMask, QuicError> Aes256PacketNumberCipher::mask(
    ByteRange sample) const {
  return maskImpl(encryptCtx_, sample);
}

constexpr size_t kAES128KeyLength = 16;

size_t Aes128PacketNumberCipher::keyLength() const {
  return kAES128KeyLength;
}

constexpr size_t kAES256KeyLength = 32;

size_t Aes256PacketNumberCipher::keyLength() const {
  return kAES256KeyLength;
}

} // namespace quic
