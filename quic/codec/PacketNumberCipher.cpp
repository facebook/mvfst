/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/PacketNumberCipher.h>

#include <quic/codec/Decode.h>

#include <quic/codec/Types.h>

namespace quic {

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

} // namespace quic
