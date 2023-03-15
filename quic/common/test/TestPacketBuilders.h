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
  folly::Optional<quic::PacketNumberSpace> maybePnSpace;
  folly::Optional<quic::PacketNum> maybeAckPacketNum;
  PacketNumStore* ackPacketNumStore{nullptr};
  folly::Optional<quic::AckBlocks> maybeAckBlocks;
  folly::Optional<std::chrono::microseconds> maybeAckDelay;
  folly::Optional<const Aead*> maybeAead; // not required
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
  RegularQuicPacketBuilder::Packet build() &&;
  quic::Buf buildBuf() &&;
  explicit AckPacketBuilder() = default;
};

struct OutstandingPacketBuilderFields {
  folly::Optional<RegularQuicWritePacket> maybePacket;
  folly::Optional<TimePoint> maybeTime;
  folly::Optional<uint32_t> maybeEncodedSize;
  folly::Optional<uint32_t> maybeEncodedBodySize;
  folly::Optional<bool> maybeIsHandshake;
  folly::Optional<uint64_t> maybeTotalBytesSent;
  folly::Optional<uint64_t> maybeTotalBodyBytesSent;
  folly::Optional<uint64_t> maybeInflightBytes;
  folly::Optional<uint64_t> maybePacketsInflight;
  folly::Optional<std::reference_wrapper<const LossState>> maybeLossState;
  folly::Optional<uint64_t> maybeWriteCount;
  folly::Optional<OutstandingPacketWrapper::Metadata::DetailsPerStream>
      maybeDetailsPerStream;
  folly::Optional<std::chrono::microseconds> maybeTotalAppLimitedTimeUsecs;
  explicit OutstandingPacketBuilderFields() = default;
};

struct OutstandingPacketBuilder : public OutstandingPacketBuilderFields {
  using Builder = OutstandingPacketBuilder;
  Builder&& setPacket(const RegularQuicWritePacket&);
  Builder&& setTime(const TimePoint& timeIn);
  Builder&& setEncodedSize(const uint32_t& encodedSizeIn);
  Builder&& setEncodedBodySize(const uint32_t& encodedBodySizeIn);
  Builder&& setIsHandshake(const bool& isHandshakeIn);
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
