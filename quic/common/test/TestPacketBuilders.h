/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicBatchWriter.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/state/AckStates.h>
#include <quic/state/StateData.h>

namespace quic::test {

struct PacketNumStore {
  quic::PacketNum nextInitialPacketNum{0};
  quic::PacketNum nextHandshakePacketNum{0};
  quic::PacketNum nextAppDataPacketNum{0};
};

struct AckPacketBuilderFields {
  QuicConnectionStateBase* dstConn{nullptr};
  Optional<quic::PacketNumberSpace> maybePnSpace;
  Optional<quic::PacketNum> maybeAckPacketNum;
  PacketNumStore* ackPacketNumStore{nullptr};
  Optional<quic::AckBlocks> maybeAckBlocks;
  OptionalMicros maybeAckDelay;
  Optional<const Aead*> maybeAead; // not required
  ProtectionType shortHeaderProtectionType{ProtectionType::KeyPhaseZero};
  explicit AckPacketBuilderFields() = default;
};

struct AckPacketBuilder : public AckPacketBuilderFields {
  using Builder = AckPacketBuilder;
  Builder&& setDstConn(QuicConnectionStateBase* dstConnIn);
  Builder&& setPacketNumberSpace(quic::PacketNumberSpace pnSpaceIn);
  Builder&& setAckPacketNum(quic::PacketNum ackPacketNumIn);
  Builder&& setAckPacketNumStore(PacketNumStore* ackPacketNumStoreIn);
  Builder&& setAckBlocks(const quic::AckBlocks& ackBlocksIn);
  Builder&& setAckDelay(std::chrono::microseconds ackDelayIn);
  Builder&& setAead(const Aead* aeadIn);
  Builder&& setShortHeaderProtectionType(ProtectionType protectionTypeIn);
  RegularQuicPacketBuilder::Packet build() &&;
  quic::Buf buildBuf() &&;
  explicit AckPacketBuilder() = default;
};

struct OutstandingPacketBuilderFields {
  Optional<RegularQuicWritePacket> maybePacket;
  Optional<TimePoint> maybeTime;
  Optional<uint16_t> maybeEncodedSize;
  Optional<uint16_t> maybeEncodedBodySize;
  Optional<uint64_t> maybeTotalBytesSent;
  Optional<uint64_t> maybeTotalBodyBytesSent;
  Optional<uint32_t> maybeInflightBytes;
  Optional<uint64_t> maybePacketsInflight;
  Optional<std::reference_wrapper<const LossState>> maybeLossState;
  Optional<uint64_t> maybeWriteCount;
  Optional<OutstandingPacketWrapper::Metadata::DetailsPerStream>
      maybeDetailsPerStream;
  OptionalMicros maybeTotalAppLimitedTimeUsecs;
  explicit OutstandingPacketBuilderFields() = default;
};

struct OutstandingPacketBuilder : public OutstandingPacketBuilderFields {
  using Builder = OutstandingPacketBuilder;
  Builder&& setPacket(const RegularQuicWritePacket&);
  Builder&& setTime(const TimePoint& timeIn);
  Builder&& setEncodedSize(const uint32_t& encodedSizeIn);
  Builder&& setEncodedBodySize(const uint32_t& encodedBodySizeIn);
  Builder&& setTotalBytesSent(const uint64_t& totalBytesSentIn);
  Builder&& setTotalBodyBytesSent(const uint64_t& totalBodyBytesSentIn);
  Builder&& setInflightBytes(const uint64_t& inflightBytesIn);
  Builder&& setPacketsInflight(const uint64_t& packetsInflightIn);
  Builder&& setLossState(
      const std::reference_wrapper<const LossState>& lossStateIn);
  Builder&& setWriteCount(const uint64_t& writeCountIn);
  Builder&& setDetailsPerStream(
      const OutstandingPacketWrapper::Metadata::DetailsPerStream&
          detailsPerStreamIn);
  Builder&& setTotalAppLimitedTimeUsecs(
      const std::chrono::microseconds& totalAppLimitedTimeUsecsIn);
  OutstandingPacketWrapper build() &&;
  explicit OutstandingPacketBuilder() = default;
};

} // namespace quic::test
