/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/test/TestPacketBuilders.h>
#include <quic/state/QuicStateFunctions.h>

namespace quic::test {

AckPacketBuilder&& AckPacketBuilder::setDstConn(
    QuicConnectionStateBase* dstConnIn) {
  dstConn = dstConnIn;
  return std::move(*this);
}

AckPacketBuilder&& AckPacketBuilder::setPacketNumberSpace(
    quic::PacketNumberSpace pnSpaceIn) {
  maybePnSpace = pnSpaceIn;
  return std::move(*this);
}

AckPacketBuilder&& AckPacketBuilder::setAckPacketNum(
    quic::PacketNum ackPacketNumIn) {
  maybeAckPacketNum = ackPacketNumIn;
  return std::move(*this);
}

AckPacketBuilder&& AckPacketBuilder::setAckPacketNumStore(
    PacketNumStore* ackPacketNumStoreIn) {
  ackPacketNumStore = ackPacketNumStoreIn;
  return std::move(*this);
}

AckPacketBuilder&& AckPacketBuilder::setAckBlocks(
    const quic::AckBlocks& ackBlocksIn) {
  maybeAckBlocks = ackBlocksIn;
  return std::move(*this);
}

AckPacketBuilder&& AckPacketBuilder::setAckDelay(
    std::chrono::microseconds ackDelayIn) {
  maybeAckDelay = ackDelayIn;
  return std::move(*this);
}

AckPacketBuilder&& AckPacketBuilder::setAead(const Aead* aeadIn) {
  maybeAead.emplace(aeadIn);
  return std::move(*this);
}

RegularQuicPacketBuilder::Packet AckPacketBuilder::build() && {
  // This function sends ACK to dstConn
  auto srcConnId =
      (CHECK_NOTNULL(dstConn)->nodeType == QuicNodeType::Client
           ? *CHECK_NOTNULL(
                 CHECK_NOTNULL(dstConn)->serverConnectionId.get_pointer())
           : *CHECK_NOTNULL(
                 CHECK_NOTNULL(dstConn)->clientConnectionId.get_pointer()));
  auto dstConnId =
      (CHECK_NOTNULL(dstConn)->nodeType == QuicNodeType::Client
           ? *CHECK_NOTNULL(
                 CHECK_NOTNULL(dstConn)->clientConnectionId.get_pointer())
           : *CHECK_NOTNULL(
                 CHECK_NOTNULL(dstConn)->serverConnectionId.get_pointer()));
  folly::Optional<PacketHeader> header;

  const auto ackPnSpace = *CHECK_NOTNULL(maybePnSpace.get_pointer());
  const auto ackPacketNum = [this, &ackPnSpace]() {
    folly::Optional<quic::PacketNum> maybeAckPacketNum;
    if (this->ackPacketNumStore) {
      CHECK(!maybeAckPacketNum.has_value());
      auto& ackPacketNumStore = *this->ackPacketNumStore;
      switch (ackPnSpace) {
        case quic::PacketNumberSpace::Initial: {
          auto& pns = ackPacketNumStore.nextInitialPacketNum;
          maybeAckPacketNum = pns;
          pns++;
          break;
        }
        case quic::PacketNumberSpace::Handshake: {
          auto& pns = ackPacketNumStore.nextHandshakePacketNum;
          maybeAckPacketNum = pns;
          pns++;
          break;
        }
        case quic::PacketNumberSpace::AppData: {
          auto& pns = ackPacketNumStore.nextAppDataPacketNum;
          maybeAckPacketNum = pns;
          pns++;
          break;
        }
      }
    }

    if (this->maybeAckPacketNum.has_value()) {
      CHECK(!maybeAckPacketNum.has_value());
      maybeAckPacketNum = this->maybeAckPacketNum;
    }

    CHECK(maybeAckPacketNum.has_value());
    return maybeAckPacketNum.value();
  }();

  if (ackPnSpace == PacketNumberSpace::Initial) {
    header = LongHeader(
        LongHeader::Types::Initial,
        srcConnId,
        dstConnId,
        ackPacketNum,
        QuicVersion::MVFST);
  } else if (ackPnSpace == PacketNumberSpace::Handshake) {
    header = LongHeader(
        LongHeader::Types::Handshake,
        srcConnId,
        dstConnId,
        ackPacketNum,
        QuicVersion::MVFST);
  } else {
    header = ShortHeader(ProtectionType::KeyPhaseZero, dstConnId, ackPacketNum);
  }
  RegularQuicPacketBuilder builder(
      CHECK_NOTNULL(dstConn)->udpSendPacketLen,
      std::move(*header),
      getAckState(*CHECK_NOTNULL(dstConn), ackPnSpace)
          .largestAckScheduled.value_or(0));
  builder.encodePacketHeader();
  if (maybeAead) {
    builder.accountForCipherOverhead(maybeAead.value()->getCipherOverhead());
  }
  DCHECK(builder.canBuildPacket());
  AckFrameMetaData ackData(
      *CHECK_NOTNULL(maybeAckBlocks.get_pointer()),
      *CHECK_NOTNULL(maybeAckDelay.get_pointer()),
      CHECK_NOTNULL(dstConn)->transportSettings.ackDelayExponent);
  writeAckFrame(ackData, builder);
  return std::move(builder).buildPacket();
}

} // namespace quic::test
