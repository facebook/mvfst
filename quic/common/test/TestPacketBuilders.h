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

} // namespace quic::test
