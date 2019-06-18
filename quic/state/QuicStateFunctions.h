/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Overload.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/state/StateData.h>
#include <quic/state/stream/StreamStateMachine.h>

namespace quic {

void updateAckSendStateOnRecvPacket(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    bool pktOutOfOrder,
    bool pktHasRetransmittableData,
    bool pktHasCryptoData);

void updateAckStateOnAckTimeout(QuicConnectionStateBase& conn);

void updateAckSendStateOnSentPacketWithAcks(
    QuicConnectionStateBase& conn,
    AckState& ackState,
    PacketNum largestAckScheduled);

void updateRtt(
    QuicConnectionStateBase& conn,
    std::chrono::microseconds rttSample,
    std::chrono::microseconds ackDelay);

template <typename Event>
void invokeStreamSendStateMachine(
    QuicConnectionStateBase&,
    QuicStreamState& stream,
    Event event) {
  invokeHandler<StreamSendStateMachine>(stream.send, std::move(event), stream);
}

template <typename Event>
void invokeStreamReceiveStateMachine(
    QuicConnectionStateBase&,
    QuicStreamState& stream,
    Event event) {
  invokeHandler<StreamReceiveStateMachine>(
      stream.recv, std::move(event), stream);
}

bool isConnectionPaced(const QuicConnectionStateBase& conn) noexcept;

AckState& getAckState(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

const AckState& getAckState(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

AckStateVersion currentAckStateVersion(
    const QuicConnectionStateBase& conn) noexcept;

PacketNum getNextPacketNum(
    const QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

void increaseNextPacketNum(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

/**
 * Update largestReceivedPacketNum in ackState with packetNum. Return if the
 * current packetNum is received out of order.
 */
template <typename ClockType = quic::Clock>
bool updateLargestReceivedPacketNum(
    AckState& ackState,
    PacketNum packetNum,
    TimePoint receivedTime) {
  PacketNum expectedNextPacket = 0;
  if (ackState.largestReceivedPacketNum) {
    expectedNextPacket = *ackState.largestReceivedPacketNum + 1;
  }
  ackState.largestReceivedPacketNum = std::max<PacketNum>(
      ackState.largestReceivedPacketNum.value_or(packetNum), packetNum);
  ackState.acks.insert(packetNum);
  if (ackState.largestReceivedPacketNum == packetNum) {
    ackState.largestRecvdPacketTime = receivedTime;
  }
  static_assert(ClockType::is_steady, "Needs steady clock");
  return expectedNextPacket != packetNum;
}

std::deque<OutstandingPacket>::iterator getNextOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace,
    std::deque<OutstandingPacket>::iterator from);
std::deque<OutstandingPacket>::iterator getFirstOutstandingPacket(
    QuicConnectionStateBase& conn,
    PacketNumberSpace packetNumberSpace);

bool hasReceivedPackets(const QuicConnectionStateBase& conn) noexcept;

bool hasReceivedPacketsAtLastCloseSent(
    const QuicConnectionStateBase& conn) noexcept;

bool hasNotReceivedNewPacketsSinceLastCloseSent(
    const QuicConnectionStateBase& conn) noexcept;

void updateLargestReceivedPacketsAtLastCloseSent(
    QuicConnectionStateBase& conn) noexcept;

folly::Optional<TimePoint>& getLossTime(
    QuicConnectionStateBase& conn,
    PacketNumberSpace pnSpace) noexcept;

std::pair<folly::Optional<TimePoint>, PacketNumberSpace> earliestLossTimer(
    const QuicConnectionStateBase& conn) noexcept;
} // namespace quic
