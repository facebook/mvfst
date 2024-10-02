/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/Types.h>
#include <quic/common/Optional.h>
#include <quic/common/SmallCollections.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/StateData.h>

namespace quic {

class AckedPacketIterator {
 public:
  AckedPacketIterator(
      const quic::ReadAckFrame::Vec& ackBlocks,
      QuicConnectionStateBase& conn,
      PacketNumberSpace pnSpace);

  OutstandingPacketWrapper& operator*();

  OutstandingPacketWrapper* operator->();

  // Erase acked outstandings, starting at outstandingsIter_ and the ack
  // block starting at ackBlockIter_. The most common use case would be to
  // just create an AckedPacketIterator, call eraseAckedOutstandings, and
  // then discard the iterator.
  void eraseAckedOutstandings();

  bool valid();

  void next();

 private:
  enum class MoveResult { SUCCESS = 0, FAILURE = 1 };

  MoveResult moveToNextValid();

  MoveResult moveToNextValidInAckBlock(const AckBlock& ackBlock);

  const quic::ReadAckFrame::Vec& ackBlocks_;
  QuicConnectionStateBase& conn_;
  PacketNumberSpace pnSpace_;
  std::deque<OutstandingPacketWrapper>::reverse_iterator outstandingsIter_;
  quic::ReadAckFrame::Vec::const_iterator ackBlockIter_;
  bool valid_{true};
};

} // namespace quic
