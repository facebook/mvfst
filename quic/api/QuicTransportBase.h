/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/api/QuicSocket.h>
#include <quic/api/QuicTransportBaseLite.h>
#include <quic/common/NetworkData.h>
#include <quic/common/events/QuicEventBase.h>
#include <quic/common/events/QuicTimer.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/Copa.h>
#include <quic/congestion_control/NewReno.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/state/StateData.h>

#include <folly/ExceptionWrapper.h>

namespace quic {

/**
 * Base class for the QUIC Transport. Implements common behavior for both
 * clients and servers. QuicTransportBase assumes the following:
 * 1. It is intended to be sub-classed and used via the subclass directly.
 * 2. Assumes that the sub-class manages its ownership via a shared_ptr.
 *    This is needed in order for QUIC to be able to live beyond the lifetime
 *    of the object that holds it to send graceful close messages to the peer.
 */
class QuicTransportBase : public QuicSocket,
                          public QuicTransportBaseLite,
                          QuicStreamPrioritiesObserver {
 public:
  QuicTransportBase(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      bool useConnectionEndWithErrorCallback = false);

  ~QuicTransportBase() override;

  void setPacingTimer(QuicTimer::SharedPtr pacingTimer) noexcept;

  Optional<ConnectionId> getClientConnectionId() const override;

  Optional<ConnectionId> getServerConnectionId() const override;

  Optional<ConnectionId> getClientChosenDestConnectionId() const override;

  const folly::SocketAddress& getOriginalPeerAddress() const override;

  const folly::SocketAddress& getLocalAddress() const override;

  const std::shared_ptr<QLogger> getQLogger() const;

  // QuicSocket interface
  bool replaySafe() const override;

  void closeGracefully() override;

  folly::Expected<size_t, LocalErrorCode> getStreamReadOffset(
      StreamId id) const override;
  folly::Expected<size_t, LocalErrorCode> getStreamWriteOffset(
      StreamId id) const override;
  folly::Expected<size_t, LocalErrorCode> getStreamWriteBufferedBytes(
      StreamId id) const override;

  TransportInfo getTransportInfo() const override;

  folly::Expected<QuicSocket::FlowControlState, LocalErrorCode>
  getConnectionFlowControl() const override;

  folly::Expected<uint64_t, LocalErrorCode> getMaxWritableOnStream(
      StreamId id) const override;

  folly::Expected<folly::Unit, LocalErrorCode> setConnectionFlowControlWindow(
      uint64_t windowSize) override;

  folly::Expected<folly::Unit, LocalErrorCode> setStreamFlowControlWindow(
      StreamId id,
      uint64_t windowSize) override;

  void unsetAllReadCallbacks() override;
  void unsetAllPeekCallbacks() override;
  void unsetAllDeliveryCallbacks() override;
  folly::Expected<folly::Unit, LocalErrorCode> pauseRead(StreamId id) override;
  folly::Expected<folly::Unit, LocalErrorCode> resumeRead(StreamId id) override;

  folly::Expected<folly::Unit, LocalErrorCode> setPeekCallback(
      StreamId id,
      PeekCallback* cb) override;

  folly::Expected<folly::Unit, LocalErrorCode> pausePeek(StreamId id) override;
  folly::Expected<folly::Unit, LocalErrorCode> resumePeek(StreamId id) override;

  folly::Expected<folly::Unit, LocalErrorCode> peek(
      StreamId id,
      const folly::Function<void(StreamId id, const folly::Range<PeekIterator>&)
                                const>& peekCallback) override;

  folly::Expected<folly::Unit, LocalErrorCode> consume(
      StreamId id,
      size_t amount) override;

  folly::Expected<folly::Unit, std::pair<LocalErrorCode, Optional<uint64_t>>>
  consume(StreamId id, uint64_t offset, size_t amount) override;

  folly::Expected<StreamGroupId, LocalErrorCode>
  createBidirectionalStreamGroup() override;
  folly::Expected<StreamGroupId, LocalErrorCode>
  createUnidirectionalStreamGroup() override;
  folly::Expected<StreamId, LocalErrorCode> createBidirectionalStreamInGroup(
      StreamGroupId groupId) override;
  folly::Expected<StreamId, LocalErrorCode> createUnidirectionalStreamInGroup(
      StreamGroupId groupId) override;
  bool isClientStream(StreamId stream) noexcept override;
  bool isServerStream(StreamId stream) noexcept override;
  StreamDirectionality getStreamDirectionality(
      StreamId stream) noexcept override;

  folly::Expected<folly::Unit, LocalErrorCode> resetStream(
      StreamId id,
      ApplicationErrorCode errorCode) override;

  folly::Expected<folly::Unit, LocalErrorCode> maybeResetStreamFromReadError(
      StreamId id,
      QuicErrorCode error) override;

  folly::Expected<folly::Unit, LocalErrorCode> setPingCallback(
      PingCallback* cb) override;

  void sendPing(std::chrono::milliseconds pingTimeout) override;

  const QuicConnectionStateBase* getState() const override {
    return conn_.get();
  }

  virtual void setAckRxTimestampsEnabled(bool enableAckRxTimestamps);

  void setEarlyDataAppParamsFunctions(
      folly::Function<bool(const Optional<std::string>&, const Buf&) const>
          validator,
      folly::Function<Buf()> getter) final;

  bool isDetachable() override;

  void detachEventBase() override;

  void attachEventBase(std::shared_ptr<QuicEventBase> evb) override;

  /**
   * Sets the maximum pacing rate in Bytes per second to be used
   * if pacing is enabled.
   */
  folly::Expected<folly::Unit, LocalErrorCode> setMaxPacingRate(
      uint64_t maxRateBytesPerSec) override;

  /**
   * Set factory to create specific congestion controller instances
   * for a given connection.
   * Deletes current congestion controller instance, to create new controller
   * call setCongestionControl() or setTransportSettings().
   */
  virtual void setCongestionControllerFactory(
      std::shared_ptr<CongestionControllerFactory> factory);

  // Subclass API.

  folly::Expected<Priority, LocalErrorCode> getStreamPriority(
      StreamId id) override;

  /**
   * Register a callback to be invoked when the stream offset was transmitted.
   *
   * Currently, an offset is considered "transmitted" if it has been written to
   * to the underlying UDP socket, indicating that it has passed through
   * congestion control and pacing. In the future, this callback may be
   * triggered by socket/NIC software or hardware timestamps.
   */
  folly::Expected<folly::Unit, LocalErrorCode> registerTxCallback(
      const StreamId id,
      const uint64_t offset,
      ByteEventCallback* cb) override;

  /**
   * Reset or send a stop sending on all non-control streams. Leaves the
   * connection otherwise unmodified. Note this will also trigger the
   * onStreamWriteError and readError callbacks immediately.
   */
  void resetNonControlStreams(
      ApplicationErrorCode error,
      folly::StringPiece errorMsg) override;

  /*
   * Set the background mode priority threshold and the target bw utilization
   * factor to use when in background mode.
   *
   * If all streams have equal or lower priority compares to the threshold
   * (value >= threshold), the connection is considered to be in background
   * mode.
   */
  void setBackgroundModeParameters(
      PriorityLevel maxBackgroundPriority,
      float backgroundUtilizationFactor);

  /*
   * Disable background mode by clearing all related parameters.
   */
  void clearBackgroundModeParameters();

  void setThrottlingSignalProvider(
      std::shared_ptr<ThrottlingSignalProvider>) override;

  virtual void setQLogger(std::shared_ptr<QLogger> qLogger);

  void setLoopDetectorCallback(std::shared_ptr<LoopDetectorCallback> callback) {
    conn_->loopDetectorCallback = std::move(callback);
  }

  /**
   * Set the read callback for Datagrams
   */
  folly::Expected<folly::Unit, LocalErrorCode> setDatagramCallback(
      DatagramCallback* cb) override;

  /**
   * Returns the maximum allowed Datagram payload size.
   * 0 means Datagram is not supported
   */
  FOLLY_NODISCARD uint16_t getDatagramSizeLimit() const override;

  /**
   * Writes a Datagram frame. If buf is larger than the size limit returned by
   * getDatagramSizeLimit(), or if the write buffer is full, buf will simply be
   * dropped, and a LocalErrorCode will be returned to caller.
   */
  folly::Expected<folly::Unit, LocalErrorCode> writeDatagram(Buf buf) override;

  /**
   * Returns the currently available received Datagrams.
   * Returns all datagrams if atMost is 0.
   */
  folly::Expected<std::vector<ReadDatagram>, LocalErrorCode> readDatagrams(
      size_t atMost = 0) override;

  /**
   * Returns the currently available received Datagram IOBufs.
   * Returns all datagrams if atMost is 0.
   */
  folly::Expected<std::vector<Buf>, LocalErrorCode> readDatagramBufs(
      size_t atMost = 0) override;

  /**
   * Set control messages to be sent for socket_ write, note that it's for this
   * specific transport and does not change the other sockets sharing the same
   * fd.
   */
  void setCmsgs(const folly::SocketCmsgMap& options);

  void appendCmsgs(const folly::SocketCmsgMap& options);

  /**
   * Sets the policy per stream group id.
   * If policy == std::nullopt, the policy is removed for corresponding stream
   * group id (reset to the default rtx policy).
   */
  folly::Expected<folly::Unit, LocalErrorCode>
  setStreamGroupRetransmissionPolicy(
      StreamGroupId groupId,
      std::optional<QuicStreamGroupRetransmissionPolicy> policy) noexcept
      override;

  [[nodiscard]] const folly::
      F14FastMap<StreamGroupId, QuicStreamGroupRetransmissionPolicy>&
      getStreamGroupRetransmissionPolicies() const {
    return conn_->retransmissionPolicies;
  }

  [[nodiscard]] QuicAsyncUDPSocket* getUdpSocket() const {
    return socket_.get();
  }

 protected:
  /*
   * Observe changes in stream priorities and handle background mode.
   *
   * Implements the QuicStreamPrioritiesObserver interface
   */
  void onStreamPrioritiesChange() override;

  folly::Expected<folly::Unit, LocalErrorCode> pauseOrResumeRead(
      StreamId id,
      bool resume);
  folly::Expected<folly::Unit, LocalErrorCode> pauseOrResumePeek(
      StreamId id,
      bool resume);
  folly::Expected<folly::Unit, LocalErrorCode> setPeekCallbackInternal(
      StreamId id,
      PeekCallback* cb) noexcept;

  void schedulePingTimeout(
      PingCallback* callback,
      std::chrono::milliseconds pingTimeout);

  // Helpers to notify all registered observers about specific events during
  // socket write (if enabled in the observer's config).
  void notifyStartWritingFromAppRateLimited() override;
  void notifyPacketsWritten(
      const uint64_t numPacketsWritten,
      const uint64_t numAckElicitingPacketsWritten,
      const uint64_t numBytesWritten) override;
  void notifyAppRateLimited() override;

  bool handshakeDoneNotified_{false};

  // TODO: This is silly. We need a better solution.
  // Uninitialied local address as a fallback answer when socket isn't bound.
  folly::SocketAddress localFallbackAddress;

  uint64_t qlogRefcnt_{0};

  // Priority level threshold for background streams
  // If all streams have equal or lower priority to the threshold
  // (value >= threshold), the connection is considered to be in background
  // mode.
  Optional<PriorityLevel> backgroundPriorityThreshold_;
  Optional<float> backgroundUtilizationFactor_;

  /**
   * Container for use in QuicTransportBase implementations.
   *
   * Contains a SocketObserverContainer and hands out weak or raw pointers.
   *
   * Weak pointers are used to meet the needs of QuicConnectionStateBase:
   *   - QuicConnectionStateBase needs a pointer to the SocketObserverContainer
   *     so that loss / ACK / other processing logic can access the observer
   *     container and send the observers notifications. There may not be a
   *     SocketObserverContainer if the QuicTransportBase implementation does
   *     not support it.
   *
   *   - A SocketObserverContainer must not outlive the instance of the
   *     QuicTransportBase implementation that it is associated with. This is
   *     because observers are notified that the object being observed has been
   *     destroyed when the container is destroyed, and thus if the container
   *     outlives the lifetime of the transport, then the observers will think
   *     the transport is still alive when it is in fact dead.

   *   - By storing a weak pointer to the SocketObserverContainer in the
   *     QuicConnectionStateBase, we provide access to the observer container
   *     without extending its lifetime. In parallel, because it is a managed
   *     pointer, we avoid the possibility of dereferencing a stale pointer
   *     (e.g., a pointer pointing to an object that has since been destroyed).
   *
   * We store a shared_ptr inside of this container and then distribute weak_ptr
   * to reduce the risk of a shared_ptr<SocketObserverContainer> mistakenly
   * being held elsewhere.
   */
  class WrappedSocketObserverContainer {
   public:
    explicit WrappedSocketObserverContainer(QuicSocket* socket)
        : observerContainer_(
              std::make_shared<SocketObserverContainer>(socket)) {}

    [[nodiscard]] SocketObserverContainer* getPtr() const {
      return observerContainer_.get();
    }

    [[nodiscard]] std::weak_ptr<SocketObserverContainer> getWeakPtr() const {
      return observerContainer_;
    }

    // deleted constructors (unnecessary, difficult to safely support)
    WrappedSocketObserverContainer(const WrappedSocketObserverContainer&) =
        delete;
    WrappedSocketObserverContainer(WrappedSocketObserverContainer&&) = delete;
    WrappedSocketObserverContainer& operator=(
        const WrappedSocketObserverContainer&) = delete;
    WrappedSocketObserverContainer& operator=(
        WrappedSocketObserverContainer&& rhs) = delete;

   private:
    std::shared_ptr<SocketObserverContainer> observerContainer_;
  };

 protected:
  void onSocketWritable() noexcept override;

 private:
  /**
   * Helper to check if using custom retransmission profiles is feasible.
   * Custom retransmission profiles are only applicable when stream groups are
   * enabled, i.e. advertisedMaxStreamGroups in transport settings is > 0.
   */
  [[nodiscard]] bool checkCustomRetransmissionProfilesEnabled() const;
};

} // namespace quic
