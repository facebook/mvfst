/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/congestion_control/QuicCCP.h>

#include <quic/congestion_control/CongestionControlFunctions.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/StateData.h>

#ifdef CCP_ENABLED
#include <ccp/ccp.h>
#include <ccp/ccp_error.h>
#endif

// The ccpDatapath field is only defined when ccp is enabled.
// When ccp is not enabled, we can safely set this to null, because an
// instance of this class cannot be created (will be denied by
// ServerCongestionControllerFactory).

namespace quic {

#ifdef CCP_ENABLED
CCP::CCP(QuicConnectionStateBase& conn)
    : conn_(static_cast<QuicServerConnectionState&>(conn)),
      endOfRecovery_(folly::none),
      inFallback_(false),
      fallbackCC_(conn) {
  cwndBytes_ = boundedCwnd(
      conn.transportSettings.initCwndInMss * conn.udpSendPacketLen,
      conn_.udpSendPacketLen,
      conn_.transportSettings.maxCwndInMss,
      conn_.transportSettings.minCwndInMss);

  datapath_ = conn_.ccpDatapath;

  struct ccp_datapath_info info = {
      .init_cwnd = static_cast<u32>(conn.transportSettings.initCwndInMss),
      .mss = static_cast<u32>(conn.udpSendPacketLen),
      // the rest is not used at the moment
      .src_ip = 0, // conn.peerAddress.getIPAddress().asV4().toLong()
      .src_port = 0, // conn.peerAddress.getPort(),
      .dst_ip = 0, // where is the destination addr?
      .dst_port = 0, // where is the destination addr?
  };

  if (!datapath_) {
    fallback();
    return;
  }

  // Inform CCP about this new connection. The returned ccp_conn_ object
  // contains per-connection state and must be passed to all other libccp
  // functions regarding this connection. We pass a reference to ourself
  // so that it can be pulled out later by CCPReader when it needs to look
  // up the correct CCP instance for a given connection id.
  ccp_conn_ = ccp_connection_start(datapath_, (void*)this, &info);
  if (ccp_conn_ == nullptr) {
    fallback();
    LOG(ERROR) << "libccp::ccp_connection_start failed\n";
  }
}

CCP::~CCP() {
  if (ccp_conn_) {
    // Inform CCP that this connection has ended and thus it can free related
    // state.
    ccp_connection_free(datapath_, ccp_conn_->index);
  }
}

void CCP::onRemoveBytesFromInflight(uint64_t bytes) {
  DCHECK_LE(bytes, conn_.lossState.inflightBytes);
  conn_.lossState.inflightBytes -= bytes;
}

void CCP::onPacketSent(const OutstandingPacket& packet) {
  if (std::numeric_limits<uint64_t>::max() - conn_.lossState.inflightBytes <
      packet.metadata.encodedSize) {
    throw QuicInternalException(
        "CCP: inflightBytes overflow", LocalErrorCode::INFLIGHT_BYTES_OVERFLOW);
  }

  if (inFallback_) {
    fallbackCC_.onPacketSent(packet);
  } else {
    // Fallback algorithm takes care of bytes acked since it shares the same
    // conn_
    addAndCheckOverflow(
        conn_.lossState.inflightBytes, packet.metadata.encodedSize);
  }

  if (conn_.qLogger) {
    conn_.qLogger->addCongestionMetricUpdate(
        conn_.lossState.inflightBytes,
        getCongestionWindow(),
        kCongestionPacketSent);
  }
}

void CCP::onAckEvent(const AckEvent& ack) {
  DCHECK(ack.largestNewlyAckedPacket.has_value() && !ack.ackedPackets.empty());

  // Fallback algorithm takes care of bytes acked since it shares the same conn_
  if (!inFallback_) {
    onRemoveBytesFromInflight(ack.ackedBytes);
  }

  // Add latest state to this batch of udpates. See comment regarding
  // ccp_primitives struct
  struct ccp_primitives* mmt = &ccp_conn_->prims;
  mmt->bytes_acked += ack.ackedBytes;
  mmt->packets_acked += ack.ackedPackets.size();
  for (const auto& packet : ack.ackedPackets) {
    if (packet.encodedSize == 0) {
      continue;
    }
    if (packet.lastAckedPacketInfo) {
      sendRate_ = Bandwidth(
          packet.totalBytesSentThen -
              packet.lastAckedPacketInfo->totalBytesSent,
          std::chrono::duration_cast<std::chrono::microseconds>(
              packet.sentTime - packet.lastAckedPacketInfo->sentTime));
      ackRate_ = Bandwidth(
          conn_.lossState.totalBytesAcked -
              packet.lastAckedPacketInfo->totalBytesAcked,
          std::chrono::duration_cast<std::chrono::microseconds>(
              ack.ackTime - packet.lastAckedPacketInfo->ackTime));
    } else if (ack.ackTime > packet.sentTime) {
      sendRate_ = Bandwidth(
          packet.encodedSize,
          std::chrono::duration_cast<std::chrono::microseconds>(
              ack.ackTime - packet.sentTime));
    }
  }
}

void CCP::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE ackEvent,
    const LossEvent* FOLLY_NULLABLE lossEvent) {
  // If we are in fallback mode, forward the call to the fallback algorithm.
  if (inFallback_) {
    fallbackCC_.onPacketAckOrLoss(ackEvent, lossEvent);
  }
  if (!ccp_conn_) {
    return;
  }

  // If we never connected to ccp in the first place, nothing else to do
  // regardless
  if (!ccp_conn_) {
    return;
  }

  /**
   * Even if we are in fallback, we finish the rest of this function so that we
   * can keep the ccp primitives up to date in case connection with CCP is
   * restored.
   */
  if (lossEvent) {
    onLossEvent(*lossEvent);
    if (conn_.pacer) {
      conn_.pacer->onPacketsLoss();
    }
  }

  if (ackEvent && ackEvent->largestNewlyAckedPacket.hasValue()) {
    onAckEvent(*ackEvent);
  }

  /**
   * The ccp_primitives struct contains the list of all statistics ccp wants to
   * know about. These are kept as up to date as possible, and fed to ccp_invoke
   * every time there's an ack or loss. Whenever ccp_invoke is called, libccp
   * internally decides whether or not to batch and send the updates. As the
   * caller, this is totally abstracted from us.
   */
  struct ccp_primitives* mmt = &ccp_conn_->prims;
  mmt->snd_cwnd = cwndBytes_;
  mmt->rtt_sample_us = conn_.lossState.srtt.count();
  mmt->bytes_in_flight = conn_.lossState.inflightBytes;
  mmt->rate_outgoing = sendRate_.normalize();
  mmt->rate_incoming = ackRate_.normalize();
  mmt->bytes_misordered = 0; // used for TCP SACK
  mmt->packets_misordered = 0; // used for TCP SACK
  /**
   * This is the heart of ccp on the datapath side. It takes the ccp_primitives
   * and runs them through the current datapath program. It handles sending
   * these in an update to ccp if necessary. It also keeps track of the fallback
   * timer internally. If the timer has expired, all calls to ccp_invoke will
   * return LIBCCP_FALLBACK_TIMED_OUT until connection with ccp is restored. To
   * get a log when this happens (once per datapath rather than per connectoion)
   * enable low level logging in libccp directly.
   */
  int ret = ccp_invoke(ccp_conn_);

  // If this is the first time we've received LIBCCP_FALLBACK_TIMED_OUT, it
  // means we need to switch modes, otherwise we're already in fallback and can
  // ignore it.
  if (ret == LIBCCP_FALLBACK_TIMED_OUT && !inFallback_) {
    fallback();
  }

  // If we're in fallback mode and libccp returned ok, then we can switch out of
  // fallback mode.
  if (ret == 0 && inFallback_) {
    restoreAfterFallback();
  }

  // If libccp returned an error code other than FALLBACK_TIMED_OUT, it
  // indicates an actual problem that we should raise an alert about.
  if (ret && ret != LIBCCP_FALLBACK_TIMED_OUT) {
    LOG(ERROR) << "libccp::ccp_invoke failed ret=" << ret;
  }

  // These measurements represent a counter since the last call to ccp_invoke,
  // so we need to reset them each time. The other measurements are just the
  // most up-to-date view of the statistics, so they can simply be overwritten
  // each time.
  mmt->bytes_acked = 0;
  mmt->packets_acked = 0;
  mmt->lost_pkts_sample = 0;
}

void CCP::fallback() {
  inFallback_ = true;
  // This just starts the fallback alg where we left off so it doesn't need to
  // restart all connections at init cwnd again.
  fallbackCC_.handoff(cwndBytes_, conn_.lossState.inflightBytes);
}

void CCP::restoreAfterFallback() {
  inFallback_ = false;
  // Pick up the cwnd where the fallback alg left off.
  setCongestionWindow(fallbackCC_.getCongestionWindow());
}

void CCP::onLossEvent(const LossEvent& loss) {
  DCHECK(
      loss.largestLostPacketNum.hasValue() &&
      loss.largestLostSentTime.hasValue());

  // Each "lost_pkt" is counted as a loss event in CCP, which will often warrant
  // a different response. This logic helps distinguish between multiple lost
  // packets within the same event and multiple distinct loss events.
  if (!endOfRecovery_ || *endOfRecovery_ < *loss.largestLostSentTime) {
    endOfRecovery_ = Clock::now();
    ccp_conn_->prims.lost_pkts_sample += loss.lostPackets;
  }

  // Fallback algorithm takes care of bytes acked since it shares the same conn_
  if (!inFallback_) {
    onRemoveBytesFromInflight(loss.lostBytes);
  }
}

void CCP::setPacingRate(uint64_t rate) noexcept {
  pacingRate_ = rate;
  if (conn_.pacer) {
    conn_.pacer->setPacingRate(rate);
  } else {
    LOG(ERROR) << "setPacingRate called but pacer is undefined!";
  }
}

uint64_t CCP::getWritableBytes() const noexcept {
  uint64_t cwndBytes = getCongestionWindow();
  return cwndBytes > conn_.lossState.inflightBytes
      ? cwndBytes - conn_.lossState.inflightBytes
      : 0;
}

uint64_t CCP::getCongestionWindow() const noexcept {
  uint64_t cwnd = cwndBytes_;
  if (inFallback_) {
    cwnd = fallbackCC_.getCongestionWindow();
  }
  return cwnd;
}

void CCP::setCongestionWindow(uint64_t cwnd) noexcept {
  cwndBytes_ = cwnd;
}

uint64_t CCP::getBytesInFlight() const noexcept {
  return conn_.lossState.inflightBytes;
}
#else

CCP::CCP(QuicConnectionStateBase& conn)
    : conn_(static_cast<QuicServerConnectionState&>(conn)),
      endOfRecovery_(folly::none),
      inFallback_(false),
      fallbackCC_(conn) {}

void CCP::onRemoveBytesFromInflight(uint64_t) {}
void CCP::onPacketSent(const OutstandingPacket&) {}
void CCP::onPacketAckOrLoss(
    const AckEvent* FOLLY_NULLABLE,
    const LossEvent* FOLLY_NULLABLE) {}
uint64_t CCP::getWritableBytes() const noexcept {
  return 0;
}
uint64_t CCP::getCongestionWindow() const noexcept {
  return 0;
}
void CCP::setCongestionWindow(uint64_t) noexcept {}
uint64_t CCP::getBytesInFlight() const noexcept {
  return 0;
}
void CCP::setPacingRate(uint64_t) noexcept {}
void CCP::onLossEvent(const LossEvent&) {}
void CCP::onAckEvent(const AckEvent&) {}
void CCP::fallback() {}
void CCP::restoreAfterFallback() {}

CCP::~CCP() = default;

#endif

CongestionControlType CCP::type() const noexcept {
  return CongestionControlType::CCP;
}

void CCP::setAppIdle(bool, TimePoint) noexcept {
  /* unsupported */
}

void CCP::setAppLimited() {
  /* unsupported */
}

bool CCP::isAppLimited() const noexcept {
  /* unsupported */
  return false;
}

} // namespace quic
