/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/EcnL4sTracker.h>

#include <quic/QuicException.h>

namespace {
using namespace std::chrono_literals;
constexpr std::chrono::microseconds kRttVirtMin = 25ms;
constexpr double kL4sWeightEwmaGain = 1 / 16.0;
} // namespace

namespace quic {

EcnL4sTracker::EcnL4sTracker(QuicConnectionStateBase& conn)
    : conn_(conn), rttVirt_(kRttVirtMin) {}

void EcnL4sTracker::onPacketAck(const AckEvent* ackEvent) {
  if (!ackEvent || conn_.ecnState != ECNState::ValidatedL4S) {
    // Nothing to track, if there is no ack event, or if L4S is not validated.
    return;
  }

  if (ackEvent->rttSample) {
    rttVirt_ = std::max(conn_.lossState.srtt, kRttVirtMin);
  }

  if (ackEvent->ackTime - lastUpdateTime_ >= rttVirt_ ||
      (ackEvent->ecnCECount > 0 && lastCEEchoed_ == 0)) {
    // It's time to update the l4s weight.
    double newECT1Echoed = int64_t(ackEvent->ecnECT1Count) - lastECT1Echoed_;
    double newCEEchoed = int64_t(ackEvent->ecnCECount) - lastCEEchoed_;

    if (newCEEchoed < 0 || newECT1Echoed < 0) {
      throw QuicTransportException(
          "Number of ACKed packets with ECT1 or CE marking moved backwards.",
          TransportErrorCode::PROTOCOL_VIOLATION);
    } else if (newCEEchoed + newECT1Echoed == 0) {
      // No new marks in the last rttVirt. Skip this ACK.
      return;
    }

    // Update the l4s weight if we have seen any CE marks on this connection.
    if (ackEvent->ecnCECount > 0) {
      if (lastCEEchoed_ == 0) {
        // First CE mark is seen. Initialize the weight to 1.0
        l4sWeight_ = 1.0;
      }
      auto frac = newCEEchoed / (newCEEchoed + newECT1Echoed);
      l4sWeight_ += kL4sWeightEwmaGain * (frac - l4sWeight_);

      if (newCEEchoed > 0) {
        // Log in qlogger
        if (conn_.qLogger) {
          conn_.qLogger->addL4sWeightUpdate(
              l4sWeight_, newECT1Echoed, newCEEchoed);
        }

        // Inform observers
        auto observerContainer = conn_.getSocketObserverContainer();
        if (observerContainer &&
            observerContainer->hasObserversForEvent<
                SocketObserverInterface::Events::l4sWeightUpdatedEvents>()) {
          observerContainer->invokeInterfaceMethod<
              SocketObserverInterface::Events::l4sWeightUpdatedEvents>(
              [event = quic::SocketObserverInterface::L4sWeightUpdateEvent(
                   l4sWeight_, newECT1Echoed, newCEEchoed)](
                  auto observer, auto observed) {
                observer->l4sWeightUpdated(observed, event);
              });
        }
      }
    }

    lastUpdateTime_ = ackEvent->ackTime;
    lastECT1Echoed_ = ackEvent->ecnECT1Count;
    lastCEEchoed_ = ackEvent->ecnCECount;
  }
}

double EcnL4sTracker::getL4sWeight() const {
  return l4sWeight_;
}

double EcnL4sTracker::getNormalizedL4sWeight() const {
  // Normalize the weight over the srtt
  return l4sWeight_ * conn_.lossState.srtt / rttVirt_;
}
} // namespace quic
