/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Conv.h>
#include <folly/lang/Bits.h>
#include <glog/logging.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/PacketNumber.h>
#include <string>

namespace quic {

PacketNumEncodingResult::PacketNumEncodingResult(
    PacketNum resultIn,
    size_t lengthIn)
    : result(resultIn), length(lengthIn) {}

PacketNumEncodingResult encodePacketNumber(
    PacketNum packetNum,
    PacketNum largestAckedPacketNum) {
  PacketNum twiceDistance = (packetNum - largestAckedPacketNum) * 2;
  // The number of bits we need to mask all set bits in twiceDistance.
  // This is 1 + floor(log2(x)).
  size_t lengthInBits = folly::findLastSet(twiceDistance);
  // Round up to bytes
  size_t lengthInBytes = lengthInBits == 0 ? 1 : (lengthInBits + 7) >> 3;
  if (lengthInBytes > 4) {
    throw QuicInternalException(
        folly::to<std::string>(
            "Impossible to encode PacketNum=",
            packetNum,
            ", largestAcked=",
            largestAckedPacketNum),
        LocalErrorCode::PACKET_NUMBER_ENCODING);
  }
  // We need a mask that's all 1 for lengthInBytes bytes. Left shift a 1 by that
  // many bits and then -1 will give us that. Or if lengthInBytes is 8, then ~0
  // will just do it.
  DCHECK_NE(lengthInBytes, 8);
  int64_t mask = (1ULL << lengthInBytes * 8) - 1;
  return PacketNumEncodingResult(packetNum & mask, lengthInBytes);
}

PacketNum decodePacketNumber(
    uint64_t encodedPacketNum,
    size_t packetNumBytes,
    PacketNum expectedNextPacketNum) {
  CHECK(packetNumBytes <= 4);
  size_t packetNumBits = 8 * packetNumBytes;
  PacketNum packetNumWin = 1ULL << packetNumBits;
  PacketNum packetNumHalfWin = packetNumWin >> 1;
  PacketNum mask = packetNumWin - 1;
  PacketNum candidate = (expectedNextPacketNum & ~mask) | encodedPacketNum;
  if (expectedNextPacketNum > packetNumHalfWin &&
      candidate <= expectedNextPacketNum - packetNumHalfWin &&
      candidate < (1ULL << 62) - packetNumWin) {
    return candidate + packetNumWin;
  }
  if (candidate > expectedNextPacketNum + packetNumHalfWin &&
      candidate >= packetNumWin) {
    return candidate - packetNumWin;
  }
  return candidate;
}

} // namespace quic
