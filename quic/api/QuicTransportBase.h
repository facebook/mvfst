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
#include <quic/common/FunctionLooper.h>
#include <quic/common/Timers.h>
#include <quic/congestion_control/CongestionControllerFactory.h>
#include <quic/congestion_control/Copa.h>
#include <quic/congestion_control/NewReno.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/state/StateData.h>

#include <folly/ExceptionWrapper.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/io/async/HHWheelTimer.h>

namespace quic {

enum class CloseState { OPEN, GRACEFUL_CLOSING, CLOSED };

/**
 * Base class for the QUIC Transport. Implements common behavior for both
 * clients and servers. QuicTransportBase assumes the following:
 * 1. It is intended to be sub-classed and used via the subclass directly.
 * 2. Assumes that the sub-class manages its ownership via a shared_ptr.
 *    This is needed in order for QUIC to be able to live beyond the lifetime
 *    of the object that holds it to send graceful close messages to the peer.
 */
class QuicTransportBase : public QuicSocket, QuicStreamPrioritiesObserver {
 public:
  QuicTransportBase(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      bool useConnectionEndWithErrorCallback = false);

  ~QuicTransportBase() override;

  void setPacingTimer(TimerHighRes::SharedPtr pacingTimer) noexcept;

  folly::EventBase* getEventBase() const override;

  folly::Optional<ConnectionId> getClientConnectionId() const override;

  folly::Optional<ConnectionId> getServerConnectionId() const override;

  folly::Optional<ConnectionId> getClientChosenDestConnectionId()
      const override;

  const folly::SocketAddress& getPeerAddress() const override;

  const folly::SocketAddress& getOriginalPeerAddress() const override;

  const folly::SocketAddress& getLocalAddress() const override;

  const std::shared_ptr<QLogger> getQLogger() const;

  // QuicSocket interface
  bool good() const override;

  bool replaySafe() const override;

  bool error() const override;

  void close(folly::Optional<QuicError> error) override;

  void closeGracefully() override;

  void closeNow(folly::Optional<QuicError> error) override;

  folly::Expected<size_t, LocalErrorCode> getStreamReadOffset(
      StreamId id) const override;
  folly::Expected<size_t, LocalErrorCode> getStreamWriteOffset(
      StreamId id) const override;
  folly::Expected<size_t, LocalErrorCode> getStreamWriteBufferedBytes(
      StreamId id) const override;

  TransportInfo getTransportInfo() const override;

  folly::Expected<StreamTransportInfo, LocalErrorCode> getStreamTransportInfo(
      StreamId id) const override;

  folly::Optional<std::string> getAppProtocol() const override;

  void setReceiveWindow(StreamId id, size_t recvWindowSize) override;

  void setSendBuffer(StreamId id, size_t maxUnacked, size_t maxUnsent) override;

  uint64_t getConnectionBufferAvailable() const override;

  uint64_t bufferSpaceAvailable() const;

  folly::Expected<QuicSocket::FlowControlState, LocalErrorCode>
  getConnectionFlowControl() const override;

  folly::Expected<QuicSocket::FlowControlState, LocalErrorCode>
  getStreamFlowControl(StreamId id) const override;

  folly::Expected<folly::Unit, LocalErrorCode> setConnectionFlowControlWindow(
      uint64_t windowSize) override;

  folly::Expected<folly::Unit, LocalErrorCode> setStreamFlowControlWindow(
      StreamId id,
      uint64_t windowSize) override;

  folly::Expected<folly::Unit, LocalErrorCode> setReadCallback(
      StreamId id,
      ReadCallback* cb,
      folly::Optional<ApplicationErrorCode> err =
          GenericApplicationErrorCode::NO_ERROR) override;
  void unsetAllReadCallbacks() override;
  void unsetAllPeekCallbacks() override;
  void unsetAllDeliveryCallbacks() override;
  folly::Expected<folly::Unit, LocalErrorCode> pauseRead(StreamId id) override;
  folly::Expected<folly::Unit, LocalErrorCode> resumeRead(StreamId id) override;
  folly::Expected<folly::Unit, LocalErrorCode> stopSending(
      StreamId id,
      ApplicationErrorCode error) override;

  folly::Expected<std::pair<Buf, bool>, LocalErrorCode> read(
      StreamId id,
      size_t maxLen) override;

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

  folly::Expected<
      folly::Unit,
      std::pair<LocalErrorCode, folly::Optional<uint64_t>>>
  consume(StreamId id, uint64_t offset, size_t amount) override;

  folly::Expected<StreamId, LocalErrorCode> createBidirectionalStream(
      bool replaySafe = true) override;
  folly::Expected<StreamId, LocalErrorCode> createUnidirectionalStream(
      bool replaySafe = true) override;
  uint64_t getNumOpenableBidirectionalStreams() const override;
  uint64_t getNumOpenableUnidirectionalStreams() const override;
  bool isClientStream(StreamId stream) noexcept override;
  bool isServerStream(StreamId stream) noexcept override;
  StreamInitiator getStreamInitiator(StreamId stream) noexcept override;
  bool isUnidirectionalStream(StreamId stream) noexcept override;
  bool isBidirectionalStream(StreamId stream) noexcept override;
  StreamDirectionality getStreamDirectionality(
      StreamId stream) noexcept override;

  folly::Expected<folly::Unit, LocalErrorCode> notifyPendingWriteOnStream(
      StreamId id,
      WriteCallback* wcb) override;

  folly::Expected<folly::Unit, LocalErrorCode> notifyPendingWriteOnConnection(
      WriteCallback* wcb) override;

  folly::Expected<folly::Unit, LocalErrorCode> unregisterStreamWriteCallback(
      StreamId id) override;

  WriteResult writeChain(
      StreamId id,
      Buf data,
      bool eof,
      ByteEventCallback* cb = nullptr) override;

  // TODO: Maybe I should virtualize DSR related APIs and only implement in
  // QuicServerTransport
  WriteResult writeBufMeta(
      StreamId id,
      const BufferMeta& data,
      bool eof,
      ByteEventCallback* cb = nullptr) override;

  WriteResult setDSRPacketizationRequestSender(
      StreamId id,
      std::unique_ptr<DSRPacketizationRequestSender> sender) override;

  folly::Expected<folly::Unit, LocalErrorCode> registerDeliveryCallback(
      StreamId id,
      uint64_t offset,
      ByteEventCallback* cb) override;

  folly::Optional<LocalErrorCode> shutdownWrite(StreamId id) override;

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

  // Interface with the Transport layer when data is available.
  // This is invoked when new data is received from the UDP socket.
  virtual void onNetworkData(
      const folly::SocketAddress& peer,
      NetworkData&& data) noexcept;

  virtual void setSupportedVersions(const std::vector<QuicVersion>& versions);

  void setConnectionSetupCallback(ConnectionSetupCallback* callback) final;

  void setConnectionCallback(ConnectionCallback* callback) final;

  void setEarlyDataAppParamsFunctions(
      folly::Function<bool(const folly::Optional<std::string>&, const Buf&)
                          const> validator,
      folly::Function<Buf()> getter) final;

  bool isDetachable() override;

  void detachEventBase() override;

  void attachEventBase(folly::EventBase* evb) override;

  folly::Optional<LocalErrorCode> setControlStream(StreamId id) override;

  /**
   * Set the initial flow control window for the connection.
   */
  void setTransportSettings(TransportSettings transportSettings) override;

  /**
   * Sets the maximum pacing rate in Bytes per second to be used
   * if pacing is enabled.
   */
  folly::Expected<folly::Unit, LocalErrorCode> setMaxPacingRate(
      uint64_t maxRateBytesPerSec) override;

  /**
   * Set a "knob". This will emit a knob frame to the peer, which the peer
   * application can act on by e.g. changing transport settings during the
   * connection.
   */
  folly::Expected<folly::Unit, LocalErrorCode>
  setKnob(uint64_t knobSpace, uint64_t knobId, Buf knobBlob) override;

  /**
   * Can Knob Frames be exchanged with the peer on this connection?
   */
  FOLLY_NODISCARD bool isKnobSupported() const override;

  /**
   * Set factory to create specific congestion controller instances
   * for a given connection.
   * Deletes current congestion controller instance, to create new controller
   * call setCongestionControl() or setTransportSettings().
   */
  virtual void setCongestionControllerFactory(
      std::shared_ptr<CongestionControllerFactory> factory);

  /**
   * Retrieve the transport settings
   */
  const TransportSettings& getTransportSettings() const override;

  // Subclass API.

  /**
   * Invoked when a new packet is read from the network.
   * peer is the address of the peer that was in the packet.
   * The sub-class may throw an exception if there was an error in processing
   * the packet in which case the connection will be closed.
   */
  virtual void onReadData(
      const folly::SocketAddress& peer,
      NetworkDataSingle&& networkData) = 0;

  /**
   * Invoked when we have to write some data to the wire.
   * The subclass may use this to start writing data to the socket.
   * It may also throw an exception in case of an error in which case the
   * connection will be closed.
   */
  virtual void writeData() = 0;

  /**
   * closeTransport is invoked on the sub-class when the transport is closed.
   * The sub-class may clean up any state during this call. The transport
   * may still be draining after this call.
   */
  virtual void closeTransport() = 0;

  /**
   * Invoked after the drain timeout has exceeded and the connection state will
   * be destroyed.
   */
  virtual void unbindConnection() = 0;

  /**
   * Returns whether or not the connection has a write cipher. This will be used
   * to decide to return the onTransportReady() callbacks.
   */
  virtual bool hasWriteCipher() const = 0;

  /**
   * Returns a shared_ptr which can be used as a guard to keep this
   * object alive.
   */
  virtual std::shared_ptr<QuicTransportBase> sharedGuard() = 0;

  folly::Expected<folly::Unit, LocalErrorCode> setStreamPriority(
      StreamId id,
      PriorityLevel level,
      bool incremental) override;

  folly::Expected<Priority, LocalErrorCode> getStreamPriority(
      StreamId id) override;

  /**
   * Invoke onCanceled on all the delivery callbacks registered for streamId.
   */
  void cancelDeliveryCallbacksForStream(StreamId id) override;

  /**
   * Invoke onCanceled on all the delivery callbacks registered for streamId for
   * offsets lower than the offset provided.
   */
  void cancelDeliveryCallbacksForStream(StreamId id, uint64_t offset) override;

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
   * Register a byte event to be triggered when specified event type occurs for
   * the specified stream and offset.
   */
  folly::Expected<folly::Unit, LocalErrorCode> registerByteEventCallback(
      const ByteEvent::Type type,
      const StreamId id,
      const uint64_t offset,
      ByteEventCallback* cb) override;

  /**
   * Cancel byte event callbacks for given stream.
   *
   * If an offset is provided, cancels only callbacks with an offset less than
   * or equal to the provided offset, otherwise cancels all callbacks.
   */
  void cancelByteEventCallbacksForStream(
      const StreamId id,
      const folly::Optional<uint64_t>& offset = folly::none) override;

  /**
   * Cancel byte event callbacks for given type and stream.
   *
   * If an offset is provided, cancels only callbacks with an offset less than
   * or equal to the provided offset, otherwise cancels all callbacks.
   */
  void cancelByteEventCallbacksForStream(
      const ByteEvent::Type type,
      const StreamId id,
      const folly::Optional<uint64_t>& offset = folly::none) override;

  /**
   * Cancel all byte event callbacks of all streams.
   */
  void cancelAllByteEventCallbacks() override;

  /**
   * Cancel all byte event callbacks of all streams of the given type.
   */
  void cancelByteEventCallbacks(const ByteEvent::Type type) override;

  /**
   * Reset or send a stop sending on all non-control streams. Leaves the
   * connection otherwise unmodified. Note this will also trigger the
   * onStreamWriteError and readError callbacks immediately.
   */
  void resetNonControlStreams(
      ApplicationErrorCode error,
      folly::StringPiece errorMsg) override;

  /**
   * Get the number of pending byte events for the given stream.
   */
  FOLLY_NODISCARD size_t
  getNumByteEventCallbacksForStream(const StreamId id) const override;

  /**
   * Get the number of pending byte events of specified type for given stream.
   */
  FOLLY_NODISCARD size_t getNumByteEventCallbacksForStream(
      const ByteEvent::Type type,
      const StreamId id) const override;

  /*
   * Set the background mode priority threshold and the target bw utilization
   * factor to use when in background mode.
   *
   * If all streams have equal or lower priority compares to the threshold
   * (value >= threshold), the connection is considered to be in backround mode.
   */
  void setBackgroundModeParameters(
      PriorityLevel maxBackgroundPriority,
      float backgroundUtilizationFactor);

  /*
   * Disable background mode by clearing all related parameters.
   */
  void clearBackgroundModeParameters();

  // Timeout functions
  class LossTimeout : public folly::HHWheelTimer::Callback {
   public:
    ~LossTimeout() override = default;

    explicit LossTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->lossTimeoutExpired();
    }

    virtual void callbackCanceled() noexcept override {
      // ignore. this usually means that the eventbase is dying, so we will be
      // canceled anyway
      return;
    }

   private:
    QuicTransportBase* transport_;
  };

  class AckTimeout : public folly::HHWheelTimer::Callback {
   public:
    ~AckTimeout() override = default;

    explicit AckTimeout(QuicTransportBase* transport) : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->ackTimeoutExpired();
    }

    virtual void callbackCanceled() noexcept override {
      // ignore. this usually means that the eventbase is dying, so we will be
      // canceled anyway
      return;
    }

   private:
    QuicTransportBase* transport_;
  };

  class PingTimeout : public folly::HHWheelTimer::Callback {
   public:
    ~PingTimeout() override = default;

    explicit PingTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->pingTimeoutExpired();
    }

    void callbackCanceled() noexcept override {
      // ignore, as this happens only when event  base dies
      return;
    }

   private:
    QuicTransportBase* transport_;
  };

  class PathValidationTimeout : public folly::HHWheelTimer::Callback {
   public:
    ~PathValidationTimeout() override = default;

    explicit PathValidationTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->pathValidationTimeoutExpired();
    }

    virtual void callbackCanceled() noexcept override {
      // ignore. this usually means that the eventbase is dying, so we will be
      // canceled anyway
      return;
    }

   private:
    QuicTransportBase* transport_;
  };

  class IdleTimeout : public folly::HHWheelTimer::Callback {
   public:
    ~IdleTimeout() override = default;

    explicit IdleTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->idleTimeoutExpired(true /* drain */);
    }

    void callbackCanceled() noexcept override {
      // skip drain when canceling the timeout, to avoid scheduling a new
      // drain timeout
      transport_->idleTimeoutExpired(false /* drain */);
    }

   private:
    QuicTransportBase* transport_;
  };

  class KeepaliveTimeout : public folly::HHWheelTimer::Callback {
   public:
    ~KeepaliveTimeout() override = default;

    explicit KeepaliveTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->keepaliveTimeoutExpired();
    }
    void callbackCanceled() noexcept override {
      // Specifically do nothing since if we got canceled we shouldn't write.
    }

   private:
    QuicTransportBase* transport_;
  };

  // DrainTimeout is a bit different from other timeouts. It needs to hold a
  // shared_ptr to the transport, since if a DrainTimeout is scheduled,
  // transport cannot die.
  class DrainTimeout : public folly::HHWheelTimer::Callback {
   public:
    ~DrainTimeout() override = default;

    explicit DrainTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->drainTimeoutExpired();
    }

   private:
    QuicTransportBase* transport_;
  };

  class D6DProbeTimeout : public folly::HHWheelTimer::Callback {
   public:
    ~D6DProbeTimeout() override = default;

    explicit D6DProbeTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->d6dProbeTimeoutExpired();
    }

   private:
    QuicTransportBase* transport_;
  };

  class D6DRaiseTimeout : public folly::HHWheelTimer::Callback {
   public:
    ~D6DRaiseTimeout() override = default;

    explicit D6DRaiseTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->d6dRaiseTimeoutExpired();
    }

   private:
    QuicTransportBase* transport_;
  };

  class D6DTxTimeout : public folly::HHWheelTimer::Callback {
   public:
    ~D6DTxTimeout() override = default;

    explicit D6DTxTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->d6dTxTimeoutExpired();
    }

   private:
    QuicTransportBase* transport_;
  };

  void scheduleLossTimeout(std::chrono::milliseconds timeout);
  void cancelLossTimeout();
  bool isLossTimeoutScheduled() const;

  // If you don't set it, the default is Cubic
  void setCongestionControl(CongestionControlType type) override;

  void describe(std::ostream& os) const;

  void setLogger(std::shared_ptr<Logger> logger) {
    conn_->logger = std::move(logger);
  }

  virtual void setQLogger(std::shared_ptr<QLogger> qLogger);

  void setLoopDetectorCallback(std::shared_ptr<LoopDetectorCallback> callback) {
    conn_->loopDetectorCallback = std::move(callback);
  }

  virtual void cancelAllAppCallbacks(const QuicError& error) noexcept;

  FOLLY_NODISCARD QuicConnectionStats getConnectionsStats() const override;

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
  void setCmsgs(const folly::SocketOptionMap& options);

  void appendCmsgs(const folly::SocketOptionMap& options);

 protected:
  void updateCongestionControlSettings(
      const TransportSettings& transportSettings);
  void processCallbacksAfterWriteData();
  void processCallbacksAfterNetworkData();
  void invokeReadDataAndCallbacks();
  void invokePeekDataAndCallbacks();
  void invokeStreamsAvailableCallbacks();
  void updateReadLooper();
  void updatePeekLooper();
  void updateWriteLooper(bool thisIteration);
  void handlePingCallbacks();
  void handleKnobCallbacks();
  void handleAckEventCallbacks();
  void handleCancelByteEventCallbacks();
  void handleNewStreamCallbacks(std::vector<StreamId>& newPeerStreams);
  void handleDeliveryCallbacks();
  void handleStreamFlowControlUpdatedCallbacks(
      std::vector<StreamId>& streamStorage);
  void handleStreamStopSendingCallbacks();
  void handleConnWritable();

  /*
   * Observe changes in stream priorities and handle background mode.
   *
   * Implements the QuicStreamPrioritiesObserver interface
   */
  void onStreamPrioritiesChange() override;

  void cleanupAckEventState();

  void runOnEvbAsync(
      folly::Function<void(std::shared_ptr<QuicTransportBase>)> func);

  void closeImpl(
      folly::Optional<QuicError> error,
      bool drainConnection = true,
      bool sendCloseImmediately = true);
  folly::Expected<folly::Unit, LocalErrorCode> pauseOrResumeRead(
      StreamId id,
      bool resume);
  folly::Expected<folly::Unit, LocalErrorCode> pauseOrResumePeek(
      StreamId id,
      bool resume);
  void checkForClosedStream();
  folly::Expected<folly::Unit, LocalErrorCode> setReadCallbackInternal(
      StreamId id,
      ReadCallback* cb,
      folly::Optional<ApplicationErrorCode> err) noexcept;
  folly::Expected<folly::Unit, LocalErrorCode> setPeekCallbackInternal(
      StreamId id,
      PeekCallback* cb) noexcept;
  folly::Expected<StreamId, LocalErrorCode> createStreamInternal(
      bool bidirectional);

  /**
   * Helper function - if given error is not set, returns a generic app error.
   * Used by close() and closeNow().
   */
  QuicError maybeSetGenericAppError(folly::Optional<QuicError> error);

  /**
   * write data to socket
   *
   * At transport layer, this is the simplest form of write. It writes data
   * out to the network, and schedule necessary timers (ack, idle, loss). It is
   * both pacing oblivious and writeLooper oblivious. Caller needs to explicitly
   * invoke updateWriteLooper afterwards if that's desired.
   */
  void writeSocketData();

  /**
   * A wrapper around writeSocketData
   *
   * writeSocketDataAndCatch protects writeSocketData in a try-catch. It also
   * dispatch the next write loop.
   */
  void writeSocketDataAndCatch();

  /**
   * Paced write data to socket when connection is paced.
   *
   * Whether connection is based will be decided by TransportSettings and
   * congection controller. When the connection is paced, this function writes
   * out a burst size of packets and let the writeLooper schedule a callback to
   * write another burst after a pacing interval if there are more data to
   * write. When the connection isn't paced, this function do a normal write.
   */
  void pacedWriteDataToSocket(bool fromTimer);

  uint64_t maxWritableOnStream(const QuicStreamState&);
  uint64_t maxWritableOnConn();

  void lossTimeoutExpired() noexcept;
  void ackTimeoutExpired() noexcept;
  void pathValidationTimeoutExpired() noexcept;
  void idleTimeoutExpired(bool drain) noexcept;
  void keepaliveTimeoutExpired() noexcept;
  void drainTimeoutExpired() noexcept;
  void pingTimeoutExpired() noexcept;
  void d6dProbeTimeoutExpired() noexcept;
  void d6dRaiseTimeoutExpired() noexcept;
  void d6dTxTimeoutExpired() noexcept;

  void setIdleTimer();
  void scheduleAckTimeout();
  void schedulePathValidationTimeout();
  void schedulePingTimeout(
      PingCallback* callback,
      std::chrono::milliseconds pingTimeout);
  void scheduleD6DRaiseTimeout();
  void scheduleD6DProbeTimeout();
  void scheduleD6DTxTimeout();

  void validateCongestionAndPacing(CongestionControlType& type);

  // Helpers to notify all registered observers about specific events during
  // socket write (if enabled in the observer's config).
  void notifyStartWritingFromAppRateLimited();
  void notifyPacketsWritten(
      const uint64_t numPacketsWritten,
      const uint64_t numAckElicitingPacketsWritten,
      const uint64_t numBytesWritten);
  void notifyAppRateLimited();

  /**
   * Callback when we receive a transport knob
   */
  virtual void onTransportKnobs(Buf knobBlob);

  struct ByteEventDetail {
    ByteEventDetail(uint64_t offsetIn, ByteEventCallback* callbackIn)
        : offset(offsetIn), callback(callbackIn) {}
    uint64_t offset;
    ByteEventCallback* callback;
  };

  using ByteEventMap = folly::F14FastMap<StreamId, std::deque<ByteEventDetail>>;
  ByteEventMap& getByteEventMap(const ByteEvent::Type type);
  FOLLY_NODISCARD const ByteEventMap& getByteEventMapConst(
      const ByteEvent::Type type) const;

  /**
   * Helper function that calls passed function for each ByteEvent type.
   *
   * Removes number of locations to update when a byte event is added.
   */
  void invokeForEachByteEventType(
      const std::function<void(const ByteEvent::Type)>& fn) {
    for (const auto& type : ByteEvent::kByteEventTypes) {
      fn(type);
    }
  }

  void invokeForEachByteEventTypeConst(
      const std::function<void(const ByteEvent::Type)>& fn) const {
    for (const auto& type : ByteEvent::kByteEventTypes) {
      fn(type);
    }
  }

  void resetConnectionCallbacks() {
    connSetupCallback_ = nullptr;
    connCallback_ = nullptr;
  }

  bool processCancelCode(const QuicError& cancelCode);
  void processConnectionSetupCallbacks(const QuicError& cancelCode);
  void processConnectionCallbacks(const QuicError& cancelCode);

  std::atomic<folly::EventBase*> evb_;
  std::unique_ptr<folly::AsyncUDPSocket> socket_;
  ConnectionSetupCallback* connSetupCallback_{nullptr};
  ConnectionCallback* connCallback_{nullptr};
  // A flag telling transport if the new onConnectionEnd(error) cb must be used.
  bool useConnectionEndWithErrorCallback_{false};

  std::
      unique_ptr<QuicConnectionStateBase, folly::DelayedDestruction::Destructor>
          conn_;

  struct ReadCallbackData {
    ReadCallback* readCb;
    bool resumed{true};
    bool deliveredEOM{false};

    ReadCallbackData(ReadCallback* readCallback) : readCb(readCallback) {}
  };

  struct PeekCallbackData {
    PeekCallback* peekCb;
    bool resumed{true};

    PeekCallbackData(PeekCallback* peekCallback) : peekCb(peekCallback) {}
  };

  folly::F14FastMap<StreamId, ReadCallbackData> readCallbacks_;
  folly::F14FastMap<StreamId, PeekCallbackData> peekCallbacks_;

  ByteEventMap deliveryCallbacks_;
  ByteEventMap txCallbacks_;

  DatagramCallback* datagramCallback_{nullptr};
  PingCallback* pingCallback_{nullptr};

  WriteCallback* connWriteCallback_{nullptr};
  std::map<StreamId, WriteCallback*> pendingWriteCallbacks_;
  CloseState closeState_{CloseState::OPEN};
  bool transportReadyNotified_{false};
  bool handshakeDoneNotified_{false};
  bool d6dProbingStarted_{false};

  LossTimeout lossTimeout_;
  AckTimeout ackTimeout_;
  PathValidationTimeout pathValidationTimeout_;
  IdleTimeout idleTimeout_;
  KeepaliveTimeout keepaliveTimeout_;
  DrainTimeout drainTimeout_;
  PingTimeout pingTimeout_;
  D6DProbeTimeout d6dProbeTimeout_;
  D6DRaiseTimeout d6dRaiseTimeout_;
  D6DTxTimeout d6dTxTimeout_;
  FunctionLooper::Ptr readLooper_;
  FunctionLooper::Ptr peekLooper_;
  FunctionLooper::Ptr writeLooper_;

  // TODO: This is silly. We need a better solution.
  // Uninitialied local address as a fallback answer when socket isn't bound.
  folly::SocketAddress localFallbackAddress;

  folly::Optional<std::string> exceptionCloseWhat_;

  uint64_t qlogRefcnt_{0};

  // Priority level threshold for background streams
  // If all streams have equal or lower priority to the threshold
  // (value >= threshold), the connection is considered to be in backround mode.
  folly::Optional<PriorityLevel> backgroundPriorityThreshold_;
  folly::Optional<float> backgroundUtilizationFactor_;
};

std::ostream& operator<<(std::ostream& os, const QuicTransportBase& qt);
} // namespace quic
