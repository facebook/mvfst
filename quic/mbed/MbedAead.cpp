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

// does not support inplace encryption just yet
std::unique_ptr<folly::IOBuf> MbedAead::inplaceEncrypt(
    std::unique_ptr<folly::IOBuf>&& plaintext,
    const folly::IOBuf* assocData,
    uint64_t seqNum) const {
  // support only unchained iobufs for now
  CHECK(!plaintext->isChained());
  CHECK(assocData == nullptr || !assocData->isChained());

  setCipherKey(MBEDTLS_ENCRYPT);

  // create IOBuf of size len(plaintext) + getCipherOverhead()
  const size_t tag_len = getCipherOverhead();
  auto ciphertext_buf = folly::IOBuf::create(plaintext->length() + tag_len);
  auto iv = getIV(seqNum);
  size_t write_size{0};

  if (mbedtls_cipher_auth_encrypt_ext(
          /*ctx=*/&cipher_ctx,
          /*iv=*/iv.data(),
          /*iv_len=*/std::min<size_t>(iv.size(), key_.iv->length()),
          /*ad=*/assocData ? assocData->data() : nullptr,
          /*ad_len=*/assocData ? assocData->length() : 0,
          /*input=*/plaintext->data(),
          /*ilen=*/plaintext->length(),
          /*output=*/ciphertext_buf->writableData(),
          /*output_len=*/ciphertext_buf->capacity(),
          /*olen=*/&write_size,
          /*tag_len=*/tag_len) != 0) {
    throw std::runtime_error("mbedtls: failed to encrypt!");
  }

  ciphertext_buf->append(write_size);
  return ciphertext_buf;
}

folly::Optional<std::unique_ptr<folly::IOBuf>> MbedAead::tryDecrypt(
    std::unique_ptr<folly::IOBuf>&& ciphertext,
    const folly::IOBuf* assocData,
    uint64_t seqNum) const {
  // support only unchained iobufs for now
  CHECK(!ciphertext->isChained());
  CHECK(assocData == nullptr || !assocData->isChained());

  setCipherKey(MBEDTLS_DECRYPT);

  // create IOBuf of size len(plaintext) - getCipherOverhead()
  const size_t tag_len = getCipherOverhead();
  auto plaintext_buf = folly::IOBuf::create(ciphertext->length());
  auto iv = getIV(seqNum);
  size_t write_size{0};

  if (mbedtls_cipher_auth_decrypt_ext(
          /*ctx=*/&cipher_ctx,
          /*iv=*/iv.data(),
          /*iv_len=*/std::min<size_t>(iv.size(), key_.iv->length()),
          /*ad=*/assocData ? assocData->data() : nullptr,
          /*ad_len=*/assocData ? assocData->length() : 0,
          /*input=*/ciphertext->data(),
          /*ilen=*/ciphertext->length(),
          /*output=*/plaintext_buf->writableData(),
          /*output_len=*/plaintext_buf->capacity(),
          /*olen=*/&write_size,
          /*tag_len=*/tag_len) != 0) {
    return folly::none;
  }
  plaintext_buf->append(write_size);
  return plaintext_buf;
}

size_t MbedAead::getCipherOverhead() const {
  return TAG_LENGTH;
}

} // namespace quic
