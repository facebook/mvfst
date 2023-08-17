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
    VLOG(2) << prefix_ << __func__;
  }

  void onDuplicatedPacketReceived() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onOutOfOrderPacketReceived() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onPacketProcessed() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onPacketSent() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onDSRPacketSent(size_t pktSize) override {
    VLOG(2) << prefix_ << __func__ << " size=" << pktSize;
  }

  void onPacketRetransmission() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onPacketLoss() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onPacketSpuriousLoss() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onPersistentCongestion() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onPacketDropped(PacketDropReason reason) override {
    VLOG(2) << prefix_ << __func__ << " reason=" << reason._to_string();
  }

  void onPacketForwarded() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onForwardedPacketReceived() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onForwardedPacketProcessed() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onClientInitialReceived(QuicVersion version) override {
    VLOG(2) << prefix_ << __func__ << " version: " << quic::toString(version);
  }

  void onConnectionRateLimited() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onConnectionWritableBytesLimited() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onNewTokenReceived() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onNewTokenIssued() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onTokenDecryptFailure() override {
    VLOG(2) << prefix_ << __func__;
  }

  // connection level metrics:
  void onNewConnection() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onConnectionClose(
      folly::Optional<QuicErrorCode> code = folly::none) override {
    VLOG(2) << prefix_ << __func__ << " reason="
            << quic::toString(code.value_or(LocalErrorCode::NO_ERROR));
  }

  void onConnectionCloseZeroBytesWritten() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onPeerAddressChanged() override {
    VLOG(2) << prefix_ << __func__;
  }

  // stream level metrics
  void onNewQuicStream() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onQuicStreamClosed() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onQuicStreamReset(QuicErrorCode code) override {
    VLOG(2) << prefix_ << __func__ << " reason=" << quic::toString(code);
  }

  // flow control / congestion control / loss recovery related metrics
  void onConnFlowControlUpdate() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onConnFlowControlBlocked() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onStatelessReset() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onStreamFlowControlUpdate() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onStreamFlowControlBlocked() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onCwndBlocked() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onInflightBytesSample(uint64_t inflightBytes) override {
    VLOG(2) << __func__ << " inflightBytes=" << inflightBytes;
  }

  void onRttSample(uint64_t rtt) override {
    VLOG(2) << __func__ << " rtt=" << rtt;
  }

  void onBandwidthSample(uint64_t bandwidth) override {
    VLOG(2) << __func__ << " bandwidth=" << bandwidth;
  }

  void onNewCongestionController(CongestionControlType type) override {
    VLOG(2) << prefix_ << __func__
            << " type=" << congestionControlTypeToString(type);
  }

  // Probe timeout counter (aka loss timeout counter)
  void onPTO() override {
    VLOG(2) << prefix_ << __func__;
  }

  // metrics to track bytes read from / written to wire
  void onRead(size_t bufSize) override {
    VLOG(2) << prefix_ << __func__ << " size=" << bufSize;
  }

  void onWrite(size_t bufSize) override {
    VLOG(2) << prefix_ << __func__ << " size=" << bufSize;
  }

  void onUDPSocketWriteError(SocketErrorType errorType) override {
    VLOG(2) << prefix_ << __func__ << " errorType=" << toString(errorType);
  }

  void onTransportKnobApplied(TransportKnobParamId knobType) override {
    VLOG(2) << prefix_ << __func__ << " knobType=" << knobType._to_string();
  }

  void onTransportKnobError(TransportKnobParamId knobType) override {
    VLOG(2) << prefix_ << __func__ << " knobType=" << knobType._to_string();
  }

  void onTransportKnobOutOfOrder(TransportKnobParamId knobType) override {
    VLOG(2) << prefix_ << __func__ << " knobType=" << knobType._to_string();
  }

  void onServerUnfinishedHandshake() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onZeroRttBuffered() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onZeroRttBufferedPruned() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onZeroRttAccepted() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onZeroRttRejected() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onDatagramRead(size_t datagramSize) override {
    VLOG(2) << prefix_ << __func__ << " size=" << datagramSize;
  }

  void onDatagramWrite(size_t datagramSize) override {
    VLOG(2) << prefix_ << __func__ << " size=" << datagramSize;
  }

  void onDatagramDroppedOnWrite() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onDatagramDroppedOnRead() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onShortHeaderPadding(size_t padSize) override {
    VLOG(2) << prefix_ << __func__ << " size=" << padSize;
  }

  void onPacerTimerLagged() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onPeerMaxUniStreamsLimitSaturated() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onPeerMaxBidiStreamsLimitSaturated() override {
    VLOG(2) << prefix_ << __func__;
  }

  void onConnectionIdCreated(size_t encodedTimes) override {
    VLOG(2) << prefix_ << __func__ << " encodedTimes=" << encodedTimes;
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
