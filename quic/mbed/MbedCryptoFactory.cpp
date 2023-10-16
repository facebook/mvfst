/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/mbed/MbedCryptoFactory.h>

#include <glog/logging.h>

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
