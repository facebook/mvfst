/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/EventBase.h>
#include <folly/portability/GMock.h>
#include <quic/QuicException.h>

#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {

class MockQuicStats : public QuicTransportStatsCallback {
 public:
  MOCK_METHOD(void, onPacketReceived, ());
  MOCK_METHOD(void, onDuplicatedPacketReceived, ());
  MOCK_METHOD(void, onOutOfOrderPacketReceived, ());
  MOCK_METHOD(void, onPacketProcessed, ());
  MOCK_METHOD(void, onPacketSent, ());
  MOCK_METHOD(void, onDSRPacketSent, (size_t));
  MOCK_METHOD(void, onPacketRetransmission, ());
  MOCK_METHOD(void, onPacketLoss, ());
  MOCK_METHOD(void, onPacketSpuriousLoss, ());
  MOCK_METHOD(void, onPersistentCongestion, ());
  MOCK_METHOD(void, onPacketDropped, (PacketDropReason));
  MOCK_METHOD(void, onPacketForwarded, ());
  MOCK_METHOD(void, onForwardedPacketReceived, ());
  MOCK_METHOD(void, onForwardedPacketProcessed, ());
  MOCK_METHOD(void, onClientInitialReceived, (QuicVersion));
  MOCK_METHOD(void, onConnectionRateLimited, ());
  MOCK_METHOD(void, onConnectionWritableBytesLimited, ());
  MOCK_METHOD(void, onNewConnection, ());
  MOCK_METHOD(void, onConnectionClose, (folly::Optional<QuicErrorCode>));
  MOCK_METHOD(void, onConnectionCloseZeroBytesWritten, ());
  MOCK_METHOD(void, onNewQuicStream, ());
  MOCK_METHOD(void, onQuicStreamClosed, ());
  MOCK_METHOD(void, onQuicStreamReset, (QuicErrorCode));
  MOCK_METHOD(void, onConnFlowControlUpdate, ());
  MOCK_METHOD(void, onConnFlowControlBlocked, ());
  MOCK_METHOD(void, onStatelessReset, ());
  MOCK_METHOD(void, onStreamFlowControlUpdate, ());
  MOCK_METHOD(void, onStreamFlowControlBlocked, ());
  MOCK_METHOD(void, onCwndBlocked, ());
  MOCK_METHOD(void, onNewCongestionController, (CongestionControlType));
  MOCK_METHOD(void, onPTO, ());
  MOCK_METHOD(void, onRead, (size_t));
  MOCK_METHOD(void, onWrite, (size_t));
  MOCK_METHOD(void, onUDPSocketWriteError, (SocketErrorType));
  MOCK_METHOD(void, onConnectionD6DStarted, ());
  MOCK_METHOD(void, onConnectionPMTURaised, ());
  MOCK_METHOD(void, onConnectionPMTUBlackholeDetected, ());
  MOCK_METHOD(void, onConnectionPMTUUpperBoundDetected, ());
  MOCK_METHOD(void, onTransportKnobApplied, (TransportKnobParamId));
  MOCK_METHOD(void, onTransportKnobError, (TransportKnobParamId));
  MOCK_METHOD(void, onServerUnfinishedHandshake, ());
  MOCK_METHOD(void, onZeroRttBuffered, ());
  MOCK_METHOD(void, onZeroRttBufferedPruned, ());
  MOCK_METHOD(void, onZeroRttAccepted, ());
  MOCK_METHOD(void, onZeroRttRejected, ());
  MOCK_METHOD(void, onDatagramRead, (size_t));
  MOCK_METHOD(void, onDatagramWrite, (size_t));
  MOCK_METHOD(void, onDatagramDroppedOnWrite, ());
  MOCK_METHOD(void, onDatagramDroppedOnRead, ());
  MOCK_METHOD(void, onNewTokenReceived, ());
  MOCK_METHOD(void, onNewTokenIssued, ());
  MOCK_METHOD(void, onTokenDecryptFailure, ());
  MOCK_METHOD(void, onShortHeaderPadding, (size_t));
  MOCK_METHOD(void, onPacerTimerLagged, ());
};

class MockQuicStatsFactory : public QuicTransportStatsCallbackFactory {
 public:
  ~MockQuicStatsFactory() override = default;

  MOCK_METHOD(std::unique_ptr<QuicTransportStatsCallback>, make, ());
};
} // namespace quic
