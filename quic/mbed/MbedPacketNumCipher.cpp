/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/mbed/MbedPacketNumCipher.h>

namespace {

/**
 * RFC9001:
 * AEAD_AES_128_GCM and AEAD_AES_128_CCM use 128-bit AES in Electronic Codebook
 * (ECB) mode. AEAD_AES_256_GCM uses 256-bit AES in ECB mode.
 */
constexpr mbedtls_cipher_type_t toMbedPacketHeaderCipherType(
    quic::CipherType cipherType) {
  switch (cipherType) {
    case quic::CipherType::AESGCM128:
      return MBEDTLS_CIPHER_AES_128_ECB;
    default:
      folly::assume_unreachable();
  }
}

} // namespace

namespace quic {

MbedPacketNumCipher::MbedPacketNumCipher(const CipherType cipherType) {
  // get cipher info
  cipher_info = CHECK_NOTNULL(
      mbedtls_cipher_info_from_type(toMbedPacketHeaderCipherType(cipherType)));

  // init cipher ctx
  mbedtls_cipher_init(&enc_ctx);

  // setup cipher with cipher_info from above
  CHECK_EQ(mbedtls_cipher_setup(&enc_ctx, cipher_info), 0);
}

MbedPacketNumCipher::~MbedPacketNumCipher() {
  // free ctx
  mbedtls_cipher_free(&enc_ctx);
}

void MbedPacketNumCipher::setKey(folly::ByteRange key) {
  key_ = folly::IOBuf::copyBuffer(key);
  size_t key_bitlen = key.size() << 3;

  // reset context
  if (mbedtls_cipher_reset(&enc_ctx) != 0) {
    throw std::runtime_error("mbedtls: cipher_reset failed!");
  }

  // setkey & operation mode on context
  if (mbedtls_cipher_setkey(
          &enc_ctx, key_->writableData(), key_bitlen, MBEDTLS_ENCRYPT) != 0) {
    throw std::runtime_error("mbedtls: cipher_setkey failed!");
  }
}

} // namespace quic
