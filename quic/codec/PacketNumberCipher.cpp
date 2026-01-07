/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/PacketNumberCipher.h>
#include <quic/common/MvfstLogging.h>

#include <quic/codec/Decode.h>

#include <quic/codec/Types.h>

namespace quic {

quic::Expected<void, QuicError> PacketNumberCipher::decipherHeader(
    ByteRange sample,
    MutableByteRange initialByte,
    MutableByteRange packetNumberBytes,
    uint8_t initialByteMask,
    uint8_t /* packetNumLengthMask */) const {
  MVCHECK_EQ(packetNumberBytes.size(), kMaxPacketNumEncodingSize);
  auto maskResult = mask(sample);
  if (maskResult.hasError()) {
    return quic::make_unexpected(maskResult.error());
  }
  HeaderProtectionMask headerMask = std::move(maskResult.value());
  // Mask size should be > packet number length + 1.
  DCHECK_GE(headerMask.size(), 5);
  initialByte.data()[0] ^= headerMask.data()[0] & initialByteMask;
  size_t packetNumLength = parsePacketNumberLength(*initialByte.data());
  for (size_t i = 0; i < packetNumLength; ++i) {
    packetNumberBytes.data()[i] ^= headerMask.data()[i + 1];
  }
  return {};
}

quic::Expected<void, QuicError> PacketNumberCipher::cipherHeader(
    ByteRange sample,
    MutableByteRange initialByte,
    MutableByteRange packetNumberBytes,
    uint8_t initialByteMask,
    uint8_t /* packetNumLengthMask */) const {
  auto maskResult = mask(sample);
  if (maskResult.hasError()) {
    return quic::make_unexpected(maskResult.error());
  }
  HeaderProtectionMask headerMask = std::move(maskResult.value());
  // Mask size should be > packet number length + 1.
  DCHECK_GE(headerMask.size(), kMaxPacketNumEncodingSize + 1);
  size_t packetNumLength = parsePacketNumberLength(*initialByte.data());
  initialByte.data()[0] ^= headerMask.data()[0] & initialByteMask;
  for (size_t i = 0; i < packetNumLength; ++i) {
    packetNumberBytes.data()[i] ^= headerMask.data()[i + 1];
  }
  return {};
}

quic::Expected<void, QuicError> PacketNumberCipher::decryptLongHeader(
    ByteRange sample,
    MutableByteRange initialByte,
    MutableByteRange packetNumberBytes) const {
  return decipherHeader(
      sample,
      initialByte,
      packetNumberBytes,
      LongHeader::kTypeBitsMask,
      LongHeader::kPacketNumLenMask);
}

quic::Expected<void, QuicError> PacketNumberCipher::decryptShortHeader(
    ByteRange sample,
    MutableByteRange initialByte,
    MutableByteRange packetNumberBytes) const {
  return decipherHeader(
      sample,
      initialByte,
      packetNumberBytes,
      ShortHeader::kTypeBitsMask,
      ShortHeader::kPacketNumLenMask);
}

quic::Expected<void, QuicError> PacketNumberCipher::encryptLongHeader(
    ByteRange sample,
    MutableByteRange initialByte,
    MutableByteRange packetNumberBytes) const {
  return cipherHeader(
      sample,
      initialByte,
      packetNumberBytes,
      LongHeader::kTypeBitsMask,
      LongHeader::kPacketNumLenMask);
}

quic::Expected<void, QuicError> PacketNumberCipher::encryptShortHeader(
    ByteRange sample,
    MutableByteRange initialByte,
    MutableByteRange packetNumberBytes) const {
  return cipherHeader(
      sample,
      initialByte,
      packetNumberBytes,
      ShortHeader::kTypeBitsMask,
      ShortHeader::kPacketNumLenMask);
}

} // namespace quic
