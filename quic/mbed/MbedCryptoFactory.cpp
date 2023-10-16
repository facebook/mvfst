/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/mbed/MbedCryptoFactory.h>

#include <glog/logging.h>

extern "C" {
#include "mbedtls/cipher.h" // @manual
#include "mbedtls/hkdf.h" // @manual
#include "mbedtls/md.h" // @manual
}

#define uchr_ptr(x) reinterpret_cast<const unsigned char*>(x)

namespace {

/**
 * from RFC8446:
 * HKDF-Expand-Label(Secret, Label, Context, Length) =
 *    HKDF-Expand(Secret, HkdfLabel, Length)
 *
 * Where HkdfLabel is specified as:
 *  struct {
 *    uint16 length = Length;
 *    opaque label<7..255> = "tls13 " + Label;
 *    opaque context<0..255> = Context;
 *    } HkdfLabel;
 */
constexpr std::string_view labelPrefix = "tls13 ";

struct HkdfLabel {
  uint16_t length;
  std::string label;
  std::string context;

  HkdfLabel(
      uint16_t length,
      folly::StringPiece label,
      std::string context = "") {
    this->length = length;
    this->label = folly::to<std::string>(labelPrefix, label);
    this->context = std::move(context);
  }

  // encodes struct into raw bytes for input label to hkdf_expand
  std::vector<uint8_t> encodeHkdfLabel() {
    // create buffer of required size
    const uint16_t encoded_size = sizeof(length) + sizeof(uint8_t) +
        label.size() + sizeof(uint8_t) + context.size();
    std::vector<uint8_t> hkdf_label(encoded_size);

    auto buf =
        folly::IOBuf::wrapBufferAsValue(hkdf_label.data(), hkdf_label.size());
    buf.clear();

    // no growth factor since length is computed above
    folly::io::Appender appender(&buf, /*growth=*/0);

    // write length
    appender.writeBE<uint16_t>(length);

    // write size of label
    appender.writeBE<uint8_t>(folly::to<uint8_t>(label.size()));
    // write label if non-empty (should always have a value)
    CHECK(!label.empty());
    appender.push(uchr_ptr(label.c_str()), label.size());

    // write size of context
    appender.writeBE<uint8_t>(folly::to<uint8_t>(context.size()));
    // write context if non-empty
    if (!context.empty()) {
      appender.push(uchr_ptr(context.c_str()), context.size());
    }

    return hkdf_label;
  }
};

} // namespace

namespace quic {

Buf MbedCryptoFactory::makeInitialTrafficSecret(
    folly::StringPiece label,
    const ConnectionId& clientDstConnId,
    QuicVersion version) const {
  // message digest info struct
  const mbedtls_md_info_t* md_info =
      CHECK_NOTNULL(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256));
  auto md_size = mbedtls_md_get_size(md_info);

  /*
   * RFC9001; This process in pseudocode is:
   *
   * initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
   * initial_secret = HKDF-Extract(initial_salt,
   *                             client_dst_connection_id)
   *
   * client_initial_secret = HKDF-Expand-Label(initial_secret,
   *                                          "client in",
   *                                          "",
   *                                          Hash.length)
   * server_initial_secret = HKDF-Expand-Label(initial_secret,
   *                                          "server in",
   *                                          "",
   *                                          Hash.length)
   */

  auto initial_secret = folly::IOBuf::create(md_size);
  folly::StringPiece salt = getQuicVersionSalt(version);
  if (mbedtls_hkdf_extract(
          /*md=*/md_info,
          /*salt=*/uchr_ptr(salt.data()),
          /*salt_len=*/salt.size(),
          /*ikm=*/clientDstConnId.data(),
          /*ikm_len=*/clientDstConnId.size(),
          /*prk=*/initial_secret->writableData()) != 0) {
    throw std::runtime_error("mbedtls: hkdf extract failed!");
  }

  // use client/server initial secret to produce 32 byte secret (quic-tls RFC)
  constexpr uint8_t kSecretLen = 32;
  auto output_key = folly::IOBuf::create(kSecretLen);
  auto hkdfLabel =
      HkdfLabel(/*length=*/kSecretLen, /*label=*/label).encodeHkdfLabel();
  if (mbedtls_hkdf_expand(
          /*md=*/md_info,
          /*prk=*/initial_secret->data(),
          /*prk_len=*/md_size,
          /*info=*/hkdfLabel.data(),
          /*info_len=*/hkdfLabel.size(),
          /*okm=*/output_key->writableData(),
          /*okm_len=*/kSecretLen) != 0) {
    throw std::runtime_error("mbedtls: hkdf expand failed!");
  }

  output_key->append(kSecretLen);
  return output_key;
}

} // namespace quic
