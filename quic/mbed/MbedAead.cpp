/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/mbed/MbedAead.h>

#include <glog/logging.h>

namespace {

constexpr uint8_t TAG_LENGTH = 16;
constexpr mbedtls_cipher_type_t toMbedCipherType(quic::CipherType cipherType) {
  switch (cipherType) {
    case quic::CipherType::AESGCM128:
      return MBEDTLS_CIPHER_AES_128_GCM;
    default:
      folly::assume_unreachable();
  }
}

} // namespace

namespace quic {

MbedAead::MbedAead(const CipherType cipherType, TrafficKey&& key)
    : key_(std::move(key)) {
  // support only unchained key & iv for now
  CHECK(!key_.key->isChained());
  CHECK(!key_.iv->isChained());

  const mbedtls_cipher_info_t* cipher_info = CHECK_NOTNULL(
      mbedtls_cipher_info_from_type(toMbedCipherType(cipherType)));

  // init cipher ctx, however defer call to mbedtls_cipher_setkey(...) until
  // ::encrypt or ::decrypt call since operation (i.e. MBEDTLS_ENCRYPT or
  // MBEDTLS_DECRYPT can only be set once)
  mbedtls_cipher_init(&cipher_ctx);
  CHECK_EQ(mbedtls_cipher_setup(&cipher_ctx, cipher_info), 0);
}

size_t MbedAead::getCipherOverhead() const {
  return TAG_LENGTH;
}

} // namespace quic
