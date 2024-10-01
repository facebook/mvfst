/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/AckedPacketIterator.h>
#include <quic/state/QuicStateFunctions.h>

namespace quic {

AckedPacketIterator::AckedPacketIterator(
    const quic::ReadAckFrame::Vec& ackBlocks,
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace)
    : ackBlocks_(ackBlocks), conn_(conn), pnSpace_(pnSpace) {
  outstandingsIter_ = getLastOutstandingPacket(
      conn,
      pnSpace,
      true /* includeDeclaredLost */,
      true /* includeScheduledForDestruction */);
  ackBlockIter_ = ackBlocks.cbegin();
  auto moveResult = moveToNextValid();
  valid_ = (moveResult == MoveResult::SUCCESS);
}

OutstandingPacketWrapper& AckedPacketIterator::operator*() {
  return *outstandingsIter_;
}

OutstandingPacketWrapper* AckedPacketIterator::operator->() {
  return &(*outstandingsIter_);
}

bool AckedPacketIterator::valid() {
  return valid_;
}

void AckedPacketIterator::next() {
  outstandingsIter_++;
  if (outstandingsIter_ == conn_.outstandings.packets.rend()) {
    valid_ = false;
    return;
  }
  moveToNextValid();
}

AckedPacketIterator::MoveResult AckedPacketIterator::moveToNextValid() {
  while (ackBlockIter_ != ackBlocks_.cend()) {
    auto moveResult = moveToNextValidInAckBlock(*ackBlockIter_);

    if (outstandingsIter_ == conn_.outstandings.packets.rend()) {
      // We've reached the end of the outstanding packets.
      valid_ = false;
      return MoveResult::FAILURE;
    }

    if (moveResult == MoveResult::SUCCESS) {
      // We've found a valid packet.
      return MoveResult::SUCCESS;
    }

    ackBlockIter_++;
  }

  valid_ = false;
  return MoveResult::FAILURE;
}

AckedPacketIterator::MoveResult AckedPacketIterator::moveToNextValidInAckBlock(
    const AckBlock& ackBlock) {
  outstandingsIter_ = std::lower_bound(
      outstandingsIter_,
      conn_.outstandings.packets.rend(),
      ackBlock.endPacket,
      [&](const auto& packetWithTime, const auto& val) {
        return packetWithTime.packet.header.getPacketSequenceNum() > val;
      });

  while (
      (outstandingsIter_ != conn_.outstandings.packets.rend()) &&
      (pnSpace_ != outstandingsIter_->packet.header.getPacketNumberSpace())) {
    outstandingsIter_++;
  }

  if ((outstandingsIter_ == conn_.outstandings.packets.rend()) ||
      (outstandingsIter_->packet.header.getPacketSequenceNum() <
       ackBlockIter_->startPacket)) {
    return MoveResult::FAILURE;
  }

  return MoveResult::SUCCESS;
}

} // namespace quic
