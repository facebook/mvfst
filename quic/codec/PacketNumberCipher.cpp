/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/PacketNumberCipher.h>
#include <quic/codec/Decode.h>

#include <quic/codec/Types.h>

namespace quic {

constexpr size_t kAES128KeyLength = 16;

void PacketNumberCipher::decipherHeader(
    folly::ByteRange sample,
    folly::MutableByteRange initialByte,
    folly::MutableByteRange packetNumberBytes,
    uint8_t initialByteMask,
    uint8_t /* packetNumLengthMask */) const {
  CHECK_EQ(packetNumberBytes.size(), kMaxPacketNumEncodingSize);
  HeaderProtectionMask headerMask = mask(sample);
  // Mask size should be > packet number length + 1.
  DCHECK_GE(headerMask.size(), 5);
  initialByte.data()[0] ^= headerMask.data()[0] & initialByteMask;
  size_t packetNumLength = parsePacketNumberLength(*initialByte.data());
  for (size_t i = 0; i < packetNumLength; ++i) {
    packetNumberBytes.data()[i] ^= headerMask.data()[i + 1];
  }
}

void PacketNumberCipher::cipherHeader(
    folly::ByteRange sample,
    folly::MutableByteRange initialByte,
    folly::MutableByteRange packetNumberBytes,
    uint8_t initialByteMask,
    uint8_t /* packetNumLengthMask */) const {
  HeaderProtectionMask headerMask = mask(sample);
  // Mask size should be > packet number length + 1.
  DCHECK_GE(headerMask.size(), kMaxPacketNumEncodingSize + 1);
  size_t packetNumLength = parsePacketNumberLength(*initialByte.data());
  initialByte.data()[0] ^= headerMask.data()[0] & initialByteMask;
  for (size_t i = 0; i < packetNumLength; ++i) {
    packetNumberBytes.data()[i] ^= headerMask.data()[i + 1];
  }
}

void PacketNumberCipher::decryptLongHeader(
    folly::ByteRange sample,
    folly::MutableByteRange initialByte,
    folly::MutableByteRange packetNumberBytes) const {
  decipherHeader(
      sample,
      initialByte,
      packetNumberBytes,
      LongHeader::kTypeBitsMask,
      LongHeader::kPacketNumLenMask);
}

void PacketNumberCipher::decryptShortHeader(
    folly::ByteRange sample,
    folly::MutableByteRange initialByte,
    folly::MutableByteRange packetNumberBytes) const {
  decipherHeader(
      sample,
      initialByte,
      packetNumberBytes,
      ShortHeader::kTypeBitsMask,
      ShortHeader::kPacketNumLenMask);
}

void PacketNumberCipher::encryptLongHeader(
    folly::ByteRange sample,
    folly::MutableByteRange initialByte,
    folly::MutableByteRange packetNumberBytes) const {
  cipherHeader(
      sample,
      initialByte,
      packetNumberBytes,
      LongHeader::kTypeBitsMask,
      LongHeader::kPacketNumLenMask);
}

void PacketNumberCipher::encryptShortHeader(
    folly::ByteRange sample,
    folly::MutableByteRange initialByte,
    folly::MutableByteRange packetNumberBytes) const {
  cipherHeader(
      sample,
      initialByte,
      packetNumberBytes,
      ShortHeader::kTypeBitsMask,
      ShortHeader::kPacketNumLenMask);
}

void Aes128PacketNumberCipher::setKey(folly::ByteRange key) {
  encryptCtx_.reset(EVP_CIPHER_CTX_new());
  if (encryptCtx_ == nullptr) {
    throw std::runtime_error("Unable to allocate an EVP_CIPHER_CTX object");
  }
  if (EVP_EncryptInit_ex(
          encryptCtx_.get(), EVP_aes_128_ecb(), nullptr, key.data(), nullptr) !=
      1) {
    throw std::runtime_error("Init error");
  }
}

HeaderProtectionMask Aes128PacketNumberCipher::mask(
    folly::ByteRange sample) const {
  HeaderProtectionMask outMask;
  CHECK_EQ(sample.size(), outMask.size());
  int outLen = 0;
  if (EVP_EncryptUpdate(
          encryptCtx_.get(),
          outMask.data(),
          &outLen,
          sample.data(),
          sample.size()) != 1 ||
      static_cast<HeaderProtectionMask::size_type>(outLen) != outMask.size()) {
    throw std::runtime_error("Encryption error");
  }
  return outMask;
}

size_t Aes128PacketNumberCipher::keyLength() const {
  return kAES128KeyLength;
}
} // namespace quic
