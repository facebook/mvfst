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
#include <quic/logging/oops_logger/OopsLogger.h>

namespace quic {

quic::Expected<void, QuicError> PacketNumberCipher::decipherHeader(
    ByteRange sample,
    MutableByteRange initialByte,
    MutableByteRange packetNumberBytes,
    uint8_t initialByteMask,
    uint8_t /* packetNumLengthMask */) const {
  PROTO_OOPS_LOG_IF(
      packetNumberBytes.size() != kMaxPacketNumEncodingSize,
      proto_oops::getThreadLocalOopsLogger(),
      "quic_packet_number_cipher",
      "invariant_violation: packet number decrypt buffer has invalid size");
  MVCHECK_EQ(packetNumberBytes.size(), kMaxPacketNumEncodingSize);
  auto maskResult = mask(sample);
  if (maskResult.hasError()) {
    return quic::make_unexpected(maskResult.error());
  }
  HeaderProtectionMask headerMask = std::move(maskResult.value());
  // Mask size should be > packet number length + 1.
  PROTO_OOPS_LOG_IF(
      headerMask.size() < 5,
      proto_oops::getThreadLocalOopsLogger(),
      "quic_packet_number_cipher",
      "invariant_violation: packet number decrypt mask is too short");
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
  PROTO_OOPS_LOG_IF(
      headerMask.size() < kMaxPacketNumEncodingSize + 1,
      proto_oops::getThreadLocalOopsLogger(),
      "quic_packet_number_cipher",
      "invariant_violation: packet number encrypt mask is too short");
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
