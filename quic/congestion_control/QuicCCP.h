/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicException.h>
#include <quic/congestion_control/Bandwidth.h>
#include <quic/congestion_control/CongestionController.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/AckEvent.h>
#include <quic/state/StateData.h>

#ifdef CCP_ENABLED
#include <ccp/ccp.h>
#endif

#include <limits>

namespace quic {

/**
 * The class defines CCP as a congestion control "algorithm", but it really acts
 * as a proxy layer between the datapath (mvfst) and CCP. Each instance of this
 * class corresponds to a separate connection that is using CCP for congestion
 * control.
 *
 * From the perspective of this class, the behavior is very simple:
 * - On each ack or loss, it updates some statistics about the connection (rtt
 * etc.)
 * - Once in a while, after updating it will batch the last few updates and send
 * them to CCP (via IPC).
 * - Asynchronously, at any time CCP may send a message (via IPC) telling this
 * connection to use a new cwnd or rate. CCPReader receives these messages,
 * looks up the correct instance of QuicCCP for that connection, and calls
 * setCongestionWindow or setPacingRate. This class does not contain any logic
 * for updating the cwnd (or rate) directly, they only change when directed by
 * CCP.
 *
 * The low-level functionality, such as batching updates, serializing them,
 * sending IPC, etc. is handled by libccp, which is a helper library provided by
 * the CCP authors.
 *
 * If, for whatever reason, mvfst has not received any responses from CCP for a
 * while, we go into "fallback" mode and use cubic instead, by simply proxying
 * the acks, losses, and cwnd updates to an internal instance of QuicCubic. If
 * connection is re-established with CCP, we leave fallback mode and pick up the
 * cwnd where cubic left off.
 *
 */
class CCP : public CongestionController {
 public:
  explicit CCP(QuicConnectionStateBase& conn);
  ~CCP() override;

  void onRemoveBytesFromInflight(uint64_t) override;
  void onPacketSent(const OutstandingPacket& packet) override;
  void onPacketAckOrLoss(
      const AckEvent* FOLLY_NULLABLE,
      const LossEvent* FOLLY_NULLABLE) override;
  void onPacketAckOrLoss(
      folly::Optional<AckEvent> ack,
      folly::Optional<LossEvent> loss) {
    onPacketAckOrLoss(ack.get_pointer(), loss.get_pointer());
  }

  FOLLY_NODISCARD uint64_t getWritableBytes() const noexcept override;
  FOLLY_NODISCARD uint64_t getCongestionWindow() const noexcept override;
  // Called (indirectly) by CCP when it wants to update the cwnd for this
  // connection.
  void setCongestionWindow(uint64_t cwnd) noexcept;
  void setAppIdle(bool, TimePoint) noexcept override;
  void setAppLimited() override;

  FOLLY_NODISCARD CongestionControlType type() const noexcept override;

  FOLLY_NODISCARD uint64_t getBytesInFlight() const noexcept;

  // Called indirectly by CCP when it wants to update the pacing rate for this
  // connection.
  void setPacingRate(uint64_t rate) noexcept;

  FOLLY_NODISCARD bool isAppLimited() const noexcept override;

  void getStats(CongestionControllerStats& /*stats*/) const override {}

 private:
  void onLossEvent(const LossEvent&);
  void onAckEvent(const AckEvent&);
  // Fallback to in-datapath congestion control impl (eg. because ccp not
  // responding)
  void fallback();
  // Go back to using CCP after a period of fallback
  void restoreAfterFallback();

 private:
  QuicServerConnectionState& conn_;
  // The current cwnd for this connection when we are not in fallback mode.
  // When we are in fallback mode, we instead use
  // fallbackCC_->getCongestionWindow().
  uint64_t cwndBytes_;
  // The current pacing rate for this connection when we are not in fallback
  // mode. When we are in fallback mode, the pacing rate is set by fallbackCC_.
  uint64_t pacingRate_{0};
  // The per-connection state needed by libccp, initialized by calling
  // libccp::ccp_connection_start in the constructor.
  struct ccp_connection* ccp_conn_{nullptr};
  // The global (per QuicServerWorker) state needed by libccp, retrieved from
  // the connection's corresponding QuicServerConnectionState.
  struct ccp_datapath* datapath_{nullptr};
  // Used to help ensure we don't count the same loss event multiple times.
  folly::Optional<TimePoint> endOfRecovery_;
  // Current estimate of the send and ack rate, two of the basic statistics sent
  // to CCP.
  Bandwidth sendRate_, ackRate_;
  // Whether or not we are in fallback mode.
  bool inFallback_;
  // An instance of QuicCubic to use during fallback mode.
  Cubic fallbackCC_;
};
} // namespace quic
