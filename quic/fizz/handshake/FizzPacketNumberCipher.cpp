/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/handshake/FizzPacketNumberCipher.h>

namespace quic {

static void setKeyImpl(
    folly::ssl::EvpCipherCtxUniquePtr& context,
    const EVP_CIPHER* cipher,
    folly::ByteRange key) {
  DCHECK_EQ(key.size(), EVP_CIPHER_key_length(cipher));
  context.reset(EVP_CIPHER_CTX_new());
  if (context == nullptr) {
    throw std::runtime_error("Unable to allocate an EVP_CIPHER_CTX object");
  }
  if (EVP_EncryptInit_ex(context.get(), cipher, nullptr, key.data(), nullptr) !=
      1) {
    throw std::runtime_error("Init error");
  }
}

static HeaderProtectionMask maskImpl(
    const folly::ssl::EvpCipherCtxUniquePtr& context,
    folly::ByteRange sample) {
  HeaderProtectionMask outMask;
  CHECK_EQ(sample.size(), outMask.size());
  int outLen = 0;
  if (EVP_EncryptUpdate(
          context.get(),
          outMask.data(),
          &outLen,
          sample.data(),
          sample.size()) != 1 ||
      static_cast<HeaderProtectionMask::size_type>(outLen) != outMask.size()) {
    throw std::runtime_error("Encryption error");
  }
  return outMask;
}

void Aes128PacketNumberCipher::setKey(folly::ByteRange key) {
  pnKey_ = folly::IOBuf::copyBuffer(key);
  return setKeyImpl(encryptCtx_, EVP_aes_128_ecb(), key);
}

void Aes256PacketNumberCipher::setKey(folly::ByteRange key) {
  pnKey_ = folly::IOBuf::copyBuffer(key);
  return setKeyImpl(encryptCtx_, EVP_aes_256_ecb(), key);
}

const Buf& Aes128PacketNumberCipher::getKey() const {
  return pnKey_;
}

const Buf& Aes256PacketNumberCipher::getKey() const {
  return pnKey_;
}

HeaderProtectionMask Aes128PacketNumberCipher::mask(
    folly::ByteRange sample) const {
  return maskImpl(encryptCtx_, sample);
}

HeaderProtectionMask Aes256PacketNumberCipher::mask(
    folly::ByteRange sample) const {
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
