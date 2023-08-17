/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <folly/functional/Invoke.h>
#include <string>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>

namespace quic {

/* Interface for Transport level stats per VIP (server)
 * Quic Transport expects applications to instantiate this per thread (and
 * do necessary aggregation at the application level).
 *
 * NOTE: since several of these methods are called for every single packets,
 * and every single connection, it is extremely important to not do any
 * blocking call in any of the implementation of these methods.
 */
class QuicTransportStatsCallback {
 public:
  enum class SocketErrorType : uint8_t {
    AGAIN,
    INVAL,
    MSGSIZE,
    NOBUFS,
    NOMEM,
    OTHER,
    MAX
  };

  virtual ~QuicTransportStatsCallback() = default;

  // packet level metrics
  virtual void onPacketReceived() = 0;

  virtual void onDuplicatedPacketReceived() = 0;

  virtual void onOutOfOrderPacketReceived() = 0;

  virtual void onPacketProcessed() = 0;

  virtual void onPacketSent() = 0;

  virtual void onDSRPacketSent(size_t pktSize) = 0;

  virtual void onPacketRetransmission() = 0;

  virtual void onPacketLoss() = 0;

  virtual void onPacketSpuriousLoss() = 0;

  virtual void onPersistentCongestion() = 0;

  virtual void onPacketDropped(quic::PacketDropReason reason) = 0;

  virtual void onPacketForwarded() = 0;

  virtual void onForwardedPacketReceived() = 0;

  virtual void onForwardedPacketProcessed() = 0;

  virtual void onClientInitialReceived(QuicVersion version) = 0;

  virtual void onConnectionRateLimited() = 0;

  virtual void onConnectionWritableBytesLimited() = 0;

  virtual void onNewTokenReceived() = 0;

  virtual void onNewTokenIssued() = 0;

  virtual void onTokenDecryptFailure() = 0;

  // connection level metrics:
  virtual void onNewConnection() = 0;

  virtual void onConnectionClose(
      folly::Optional<QuicErrorCode> code = folly::none) = 0;

  virtual void onConnectionCloseZeroBytesWritten() = 0;

  virtual void onPeerAddressChanged() = 0;

  // stream level metrics
  virtual void onNewQuicStream() = 0;

  virtual void onQuicStreamClosed() = 0;

  virtual void onQuicStreamReset(QuicErrorCode code) = 0;

  // flow control / congestion control / loss recovery related metrics
  virtual void onConnFlowControlUpdate() = 0;

  virtual void onConnFlowControlBlocked() = 0;

  virtual void onStatelessReset() = 0;

  virtual void onStreamFlowControlUpdate() = 0;

  virtual void onStreamFlowControlBlocked() = 0;

  virtual void onCwndBlocked() = 0;

  virtual void onInflightBytesSample(uint64_t) = 0;

  virtual void onRttSample(uint64_t) = 0;

  virtual void onBandwidthSample(uint64_t) = 0;

  virtual void onNewCongestionController(CongestionControlType type) = 0;

  // retransmission timeout counter
  virtual void onPTO() = 0;

  // metrics to track bytes read from / written to wire
  virtual void onRead(size_t bufSize) = 0;

  virtual void onWrite(size_t bufSize) = 0;

  virtual void onUDPSocketWriteError(SocketErrorType errorType) = 0;

  virtual void onTransportKnobApplied(TransportKnobParamId knobType) = 0;

  virtual void onTransportKnobError(TransportKnobParamId knobType) = 0;

  virtual void onTransportKnobOutOfOrder(TransportKnobParamId knobType) = 0;

  virtual void onServerUnfinishedHandshake() = 0;

  virtual void onZeroRttBuffered() = 0;

  virtual void onZeroRttBufferedPruned() = 0;

  virtual void onZeroRttAccepted() = 0;

  virtual void onZeroRttRejected() = 0;

  virtual void onDatagramRead(size_t datagramSize) = 0;

  virtual void onDatagramWrite(size_t datagramSize) = 0;

  virtual void onDatagramDroppedOnWrite() = 0;

  virtual void onDatagramDroppedOnRead() = 0;

  virtual void onShortHeaderPadding(size_t padSize) = 0;

  virtual void onPacerTimerLagged() = 0;

  virtual void onPeerMaxUniStreamsLimitSaturated() = 0;

  virtual void onPeerMaxBidiStreamsLimitSaturated() = 0;

  virtual void onConnectionIdCreated(size_t encodedTimes) = 0;

  static const char* toString(SocketErrorType errorType) {
    switch (errorType) {
      case SocketErrorType::AGAIN:
        return "AGAIN";
      case SocketErrorType::INVAL:
        return "INVAL";
      case SocketErrorType::MSGSIZE:
        return "MSGSIZE";
      case SocketErrorType::NOBUFS:
        return "NOBUFS";
      case SocketErrorType::NOMEM:
        return "NOMEM";
      case SocketErrorType::OTHER:
        return "Other";
      default:
        throw std::runtime_error("Undefined SocketErrorType");
    }
  }

  static SocketErrorType errnoToSocketErrorType(int err) {
    switch (err) {
      case EAGAIN:
        return SocketErrorType::AGAIN;
      case EINVAL:
        return SocketErrorType::INVAL;
      case EMSGSIZE:
        return SocketErrorType::MSGSIZE;
      case ENOBUFS:
        return SocketErrorType::NOBUFS;
      case ENOMEM:
        return SocketErrorType::NOMEM;
      default:
        return SocketErrorType::OTHER;
    }
  }
};

/**
 * Interface to create QuicTransportStatsCallback instance.
 * If application supplies the implementation of this factory, the transport
 * calls 'make' during its initialization _for each worker_.
 * Further, 'make' is called from the worker's eventbase so that it is
 * convenient for application to specify actions such as scheduling per thread
 * aggregation
 */
class QuicTransportStatsCallbackFactory {
 public:
  virtual ~QuicTransportStatsCallbackFactory() = default;

  virtual std::unique_ptr<QuicTransportStatsCallback> make() = 0;
};

#define QUIC_STATS(statsCallback, method, ...)                              \
  if (statsCallback) {                                                      \
    folly::invoke(                                                          \
        &QuicTransportStatsCallback::method, statsCallback, ##__VA_ARGS__); \
  }

#define QUIC_STATS_FOR_EACH(iterBegin, iterEnd, statsCallback, method, ...)   \
  if (statsCallback) {                                                        \
    std::for_each(iterBegin, iterEnd, [&](const auto&) {                      \
      folly::invoke(                                                          \
          &QuicTransportStatsCallback::method, statsCallback, ##__VA_ARGS__); \
    });                                                                       \
  }
} // namespace quic
