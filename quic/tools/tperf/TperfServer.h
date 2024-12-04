/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <string>

#include <quic/observer/SocketObserverTypes.h>
#include <quic/server/AcceptObserver.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransport.h>
#include <quic/server/QuicSharedUDPSocketFactory.h>

namespace {

class TPerfObserver : public quic::LegacyObserver {
 public:
  using LegacyObserver::LegacyObserver;
  TPerfObserver(
      EventSet eventSet,
      bool logAppRateLimited,
      bool logLoss,
      bool logRttSample)
      : quic::LegacyObserver(eventSet),
        logAppRateLimited_(logAppRateLimited),
        logLoss_(logLoss),
        logRttSample_(logRttSample) {}

  void appRateLimited(
      quic::QuicSocketLite* /* socket */,
      const quic::SocketObserverInterface::
          AppLimitedEvent& /* appLimitedEvent */) override {
    if (logAppRateLimited_) {
      LOG(INFO) << "appRateLimited detected";
    }
  }

  void packetLossDetected(
      quic::QuicSocketLite*, /* socket */
      const struct LossEvent& /* lossEvent */) override {
    if (logLoss_) {
      LOG(INFO) << "packetLoss detected";
    }
  }

  void rttSampleGenerated(
      quic::QuicSocketLite*, /* socket */
      const PacketRTT& /* RTT sample */) override {
    if (logRttSample_) {
      LOG(INFO) << "rttSample generated";
    }
  }

 private:
  bool logAppRateLimited_;
  bool logLoss_;
  bool logRttSample_;
};

/**
 * A helper acceptor observer that installs life cycle observers to
 * transport upon accept
 */
class TPerfAcceptObserver : public quic::AcceptObserver {
 public:
  TPerfAcceptObserver(bool logAppRateLimited, bool logLoss, bool logRttSample) {
    // Create an observer config, only enabling events we are interested in
    // receiving.
    quic::LegacyObserver::EventSet eventSet;
    eventSet.enable(
        quic::SocketObserverInterface::Events::appRateLimitedEvents,
        quic::SocketObserverInterface::Events::rttSamples,
        quic::SocketObserverInterface::Events::lossEvents);
    tperfObserver_ = std::make_unique<TPerfObserver>(
        eventSet, logAppRateLimited, logLoss, logRttSample);
  }

  void accept(quic::QuicTransportBase* transport) noexcept override {
    transport->addObserver(tperfObserver_.get());
  }

  void acceptorDestroy(quic::QuicServerWorker* /* worker */) noexcept override {
    LOG(INFO) << "quic server worker destroyed";
  }

  void observerAttach(quic::QuicServerWorker* /* worker */) noexcept override {
    LOG(INFO) << "TPerfAcceptObserver attached";
  }

  void observerDetach(quic::QuicServerWorker* /* worker */) noexcept override {
    LOG(INFO) << "TPerfAcceptObserver detached";
  }

 private:
  std::unique_ptr<TPerfObserver> tperfObserver_;
};
} // namespace

namespace quic::tperf {

class TPerfServer {
 public:
  class DoneCallback {
   public:
    virtual ~DoneCallback() = default;
    virtual void onDone(const std::string& msg) = 0;
  };

  explicit TPerfServer(
      const std::string& host,
      uint16_t port,
      uint64_t blockSize,
      uint64_t writesPerLoop,
      quic::CongestionControlType congestionControlType,
      bool gso,
      uint32_t maxCwndInMss,
      bool pacing,
      uint32_t numStreams,
      uint64_t maxBytesPerStream,
      uint32_t maxReceivePacketSize,
      bool useInplaceWrite,
      bool dsrEnabled,
      bool overridePacketSize,
      double latencyFactor,
      bool useAckReceiveTimestamps,
      uint32_t maxAckReceiveTimestampsToSend,
      bool useL4sEcn,
      bool readEcn,
      uint32_t dscp,
      uint32_t numServerWorkers,
      uint32_t burstDeadlineMs,
      uint64_t maxPacingRate,
      bool logAppRateLimited,
      bool logLoss,
      bool logRttSample,
      std::string qloggerPath,
      const std::string& pacingObserver,
      DoneCallback* doneCallback = nullptr);

  void start();

 private:
  std::string host_;
  uint16_t port_;
  folly::EventBase eventBase_;
  std::unique_ptr<TPerfAcceptObserver> acceptObserver_;
  std::shared_ptr<quic::QuicServer> server_;
  double latencyFactor_;
  bool useAckReceiveTimestamps_{false};
  uint32_t maxAckReceiveTimestampsToSend_;
  bool useL4sEcn_{false};
  bool readEcn_{false};
  uint32_t dscp_;
  uint32_t numServerWorkers_;
  uint32_t burstDeadlineMs_;
  uint64_t maxPacingRate_;
};

} // namespace quic::tperf
