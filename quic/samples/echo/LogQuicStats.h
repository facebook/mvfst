/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <glog/logging.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/Types.h>
#include <quic/state/QuicTransportStatsCallback.h>

namespace quic {
namespace samples {
class LogQuicStats : public quic::QuicTransportStatsCallback {
 public:
  explicit LogQuicStats(const std::string& prefix) : prefix_(prefix + " ") {}

  ~LogQuicStats() override = default;

  void onPacketReceived() override {
    VLOG(2) << prefix_ << "onPacketReceived";
  }

  void onDuplicatedPacketReceived() override {
    VLOG(2) << prefix_ << "onDuplicatedPacketReceived";
  }

  void onOutOfOrderPacketReceived() override {
    VLOG(2) << prefix_ << "onOutOfOrderPacketReceived";
  }

  void onPacketProcessed() override {
    VLOG(2) << prefix_ << "onPacketProcessed";
  }

  void onPacketSent() override {
    VLOG(2) << prefix_ << "onPacketSent";
  }

  void onDSRPacketSent(size_t pktSize) override {
    VLOG(2) << prefix_ << "onDSRPacketSent size=" << pktSize;
  }

  void onPacketRetransmission() override {
    VLOG(2) << prefix_ << "onPacketRetransmission";
  }

  void onPacketLoss() override {
    VLOG(2) << prefix_ << "onPacketLoss";
  }

  void onPacketSpuriousLoss() override {
    VLOG(2) << prefix_ << "onPacketSpuriousLoss";
  }

  void onPersistentCongestion() override {
    VLOG(2) << prefix_ << "onPersistentCongestion";
  }

  void onPacketDropped(PacketDropReason reason) override {
    VLOG(2) << prefix_ << "onPacketDropped reason=" << toString(reason);
  }

  void onPacketForwarded() override {
    VLOG(2) << prefix_ << "onPacketForwarded";
  }

  void onForwardedPacketReceived() override {
    VLOG(2) << prefix_ << "onForwardedPacketReceived";
  }

  void onForwardedPacketProcessed() override {
    VLOG(2) << prefix_ << "onForwardedPacketProcessed";
  }

  void onClientInitialReceived(QuicVersion version) override {
    VLOG(2) << prefix_
            << "onClientInitialReceived, version: " << quic::toString(version);
  }

  void onConnectionRateLimited() override {
    VLOG(2) << prefix_ << "onConnectionRateLimited";
  }

  void onConnectionWritableBytesLimited() override {
    VLOG(2) << prefix_ << "onConnectionWritableBytesLimited";
  }

  void onNewTokenReceived() override {
    VLOG(2) << prefix_ << "onNewTokenReceived";
  }

  void onNewTokenIssued() override {
    VLOG(2) << prefix_ << "onNewTokenIssued";
  }

  void onTokenDecryptFailure() override {
    VLOG(2) << prefix_ << "onTokenDecryptFailure";
  }

  // connection level metrics:
  void onNewConnection() override {
    VLOG(2) << prefix_ << "onNewConnection";
  }

  void onConnectionClose(
      folly::Optional<QuicErrorCode> code = folly::none) override {
    VLOG(2) << prefix_ << "onConnectionClose reason="
            << quic::toString(code.value_or(LocalErrorCode::NO_ERROR));
  }

  void onConnectionCloseZeroBytesWritten() override {
    VLOG(2) << prefix_ << "onConnectionCloseZeroBytesWritten";
  }

  // stream level metrics
  void onNewQuicStream() override {
    VLOG(2) << prefix_ << "onNewQuicStream";
  }

  void onQuicStreamClosed() override {
    VLOG(2) << prefix_ << "onQuicStreamClosed";
  }

  void onQuicStreamReset(QuicErrorCode code) override {
    VLOG(2) << prefix_ << "onQuicStreamReset reason=" << quic::toString(code);
  }

  // flow control / congestion control / loss recovery related metrics
  void onConnFlowControlUpdate() override {
    VLOG(2) << prefix_ << "onConnFlowControlUpdate";
  }

  void onConnFlowControlBlocked() override {
    VLOG(2) << prefix_ << "onConnFlowControlBlocked";
  }

  void onStatelessReset() override {
    VLOG(2) << prefix_ << "onStatelessReset";
  }

  void onStreamFlowControlUpdate() override {
    VLOG(2) << prefix_ << "onStreamFlowControlUpdate";
  }

  void onStreamFlowControlBlocked() override {
    VLOG(2) << prefix_ << "onStreamFlowControlBlocked";
  }

  void onCwndBlocked() override {
    VLOG(2) << prefix_ << "onCwndBlocked";
  }

  void onNewCongestionController(CongestionControlType type) override {
    VLOG(2) << prefix_ << "onNewCongestionController type="
            << congestionControlTypeToString(type);
  }

  // Probe timeout counter (aka loss timeout counter)
  void onPTO() override {
    VLOG(2) << prefix_ << "onPTO";
  }

  // metrics to track bytes read from / written to wire
  void onRead(size_t bufSize) override {
    VLOG(2) << prefix_ << "onRead size=" << bufSize;
  }

  void onWrite(size_t bufSize) override {
    VLOG(2) << prefix_ << "onWrite size=" << bufSize;
  }

  void onUDPSocketWriteError(SocketErrorType errorType) override {
    VLOG(2) << prefix_
            << "onUDPSocketWriteError errorType=" << toString(errorType);
  }

  void onConnectionD6DStarted() override {
    VLOG(2) << prefix_ << "onConnectionD6DStarted";
  }

  void onConnectionPMTURaised() override {
    VLOG(2) << prefix_ << "onConnectionPMTURaised";
  }

  void onConnectionPMTUBlackholeDetected() override {
    VLOG(2) << prefix_ << "onConnectionPMTUBlackholeDetected";
  }

  void onConnectionPMTUUpperBoundDetected() override {
    VLOG(2) << prefix_ << "onConnectionPMTUUpperBoundDetected";
  }

  void onTransportKnobApplied(TransportKnobParamId knobType) override {
    VLOG(2) << prefix_
            << "onTransportKnobApplied knobType=" << knobType._to_string();
  }

  void onTransportKnobError(TransportKnobParamId knobType) override {
    VLOG(2) << prefix_
            << "onTransportKnboError knobType=" << knobType._to_string();
  }

  void onServerUnfinishedHandshake() override {
    VLOG(2) << prefix_ << "onServerUnfinishedHandshake";
  }

  void onZeroRttBuffered() override {
    VLOG(2) << prefix_ << "onZeroRttBuffered";
  }

  void onZeroRttBufferedPruned() override {
    VLOG(2) << prefix_ << "onZeroRttBufferedPruned";
  }

  void onZeroRttAccepted() override {
    VLOG(2) << prefix_ << "onZeroRttAccepted";
  }

  void onZeroRttRejected() override {
    VLOG(2) << prefix_ << "onZeroRttRejected";
  }

  void onDatagramRead(size_t datagramSize) override {
    VLOG(2) << prefix_ << "onDatagramRead size=" << datagramSize;
  }

  void onDatagramWrite(size_t datagramSize) override {
    VLOG(2) << prefix_ << "onDatagramWrite size=" << datagramSize;
  }

  void onDatagramDroppedOnWrite() override {
    VLOG(2) << prefix_ << "onDatagramDroppedOnWrite";
  }

  void onDatagramDroppedOnRead() override {
    VLOG(2) << prefix_ << "onDatagramDroppedOnRead";
  }

  void onShortHeaderPadding(size_t padSize) override {
    VLOG(2) << prefix_ << "onShortHeaderPadding size=" << padSize;
  }

  void onPacerTimerLagged() override {
    VLOG(2) << prefix_ << __func__;
  }

 private:
  std::string prefix_;
};

class LogQuicStatsFactory : public QuicTransportStatsCallbackFactory {
 public:
  ~LogQuicStatsFactory() override = default;

  std::unique_ptr<QuicTransportStatsCallback> make() override {
    return std::make_unique<LogQuicStats>("server");
  }
};

} // namespace samples
} // namespace quic
