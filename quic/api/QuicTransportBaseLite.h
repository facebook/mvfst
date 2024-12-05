/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocketLite.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/FunctionLooper.h>

namespace quic {

enum class CloseState { OPEN, GRACEFUL_CLOSING, CLOSED };

class QuicTransportBaseLite : virtual public QuicSocketLite,
                              QuicAsyncUDPSocket::WriteCallback {
 public:
  QuicTransportBaseLite(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      bool useConnectionEndWithErrorCallback = false);

  /**
   * Invoked when we have to write some data to the wire.
   * The subclass may use this to start writing data to the socket.
   * It may also throw an exception in case of an error in which case the
   * connection will be closed.
   */
  virtual void writeData() = 0;

  // Interface with the Transport layer when data is available.
  // This is invoked when new data is received from the UDP socket.
  virtual void onNetworkData(
      const folly::SocketAddress& peer,
      NetworkData&& data) noexcept;

  /**
   * Invoked when a new packet is read from the network.
   * peer is the address of the peer that was in the packet.
   * The sub-class may throw an exception if there was an error in processing
   * the packet in which case the connection will be closed.
   */
  virtual void onReadData(
      const folly::SocketAddress& peer,
      ReceivedUdpPacket&& udpPacket) = 0;

  void close(Optional<QuicError> error) override;

  void closeNow(Optional<QuicError> error) override;

  folly::Expected<folly::Unit, LocalErrorCode> stopSending(
      StreamId id,
      ApplicationErrorCode error) override;

  folly::Expected<StreamId, LocalErrorCode> createBidirectionalStream(
      bool replaySafe = true) override;
  folly::Expected<StreamId, LocalErrorCode> createUnidirectionalStream(
      bool replaySafe = true) override;
  uint64_t getNumOpenableBidirectionalStreams() const override;
  uint64_t getNumOpenableUnidirectionalStreams() const override;
  bool isUnidirectionalStream(StreamId stream) noexcept override;
  bool isBidirectionalStream(StreamId stream) noexcept override;

  WriteResult writeChain(
      StreamId id,
      Buf data,
      bool eof,
      ByteEventCallback* cb = nullptr) override;

  Optional<LocalErrorCode> shutdownWrite(StreamId id) override;

  folly::Expected<folly::Unit, LocalErrorCode> registerDeliveryCallback(
      StreamId id,
      uint64_t offset,
      ByteEventCallback* cb) override;

  folly::Expected<folly::Unit, LocalErrorCode> notifyPendingWriteOnStream(
      StreamId id,
      StreamWriteCallback* wcb) override;

  folly::Expected<folly::Unit, LocalErrorCode> notifyPendingWriteOnConnection(
      ConnectionWriteCallback* wcb) override;

  folly::Expected<folly::Unit, LocalErrorCode> unregisterStreamWriteCallback(
      StreamId id) override;

  folly::Expected<folly::Unit, LocalErrorCode> resetStream(
      StreamId id,
      ApplicationErrorCode errorCode) override;

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
   * Cancel byte event callbacks for given stream.
   *
   * If an offset is provided, cancels only callbacks with an offset less than
   * or equal to the provided offset, otherwise cancels all callbacks.
   */
  void cancelByteEventCallbacksForStream(
      const StreamId id,
      const Optional<uint64_t>& offset = none) override;

  /**
   * Cancel byte event callbacks for given type and stream.
   *
   * If an offset is provided, cancels only callbacks with an offset less than
   * or equal to the provided offset, otherwise cancels all callbacks.
   */
  void cancelByteEventCallbacksForStream(
      const ByteEvent::Type type,
      const StreamId id,
      const Optional<uint64_t>& offset = none) override;

  /**
   * Register a byte event to be triggered when specified event type occurs for
   * the specified stream and offset.
   */
  folly::Expected<folly::Unit, LocalErrorCode> registerByteEventCallback(
      const ByteEvent::Type type,
      const StreamId id,
      const uint64_t offset,
      ByteEventCallback* cb) override;

  bool good() const override;

  bool error() const override;

  uint64_t bufferSpaceAvailable() const;

  /**
   * Returns whether or not the connection has a write cipher. This will be used
   * to decide to return the onTransportReady() callbacks.
   */
  virtual bool hasWriteCipher() const = 0;

  void setConnectionSetupCallback(
      folly::MaybeManagedPtr<ConnectionSetupCallback> callback) final;

  void setConnectionCallback(
      folly::MaybeManagedPtr<ConnectionCallback> callback) final;

  Optional<LocalErrorCode> setControlStream(StreamId id) override;

  folly::Expected<folly::Unit, LocalErrorCode> setReadCallback(
      StreamId id,
      ReadCallback* cb,
      Optional<ApplicationErrorCode> err =
          GenericApplicationErrorCode::NO_ERROR) override;

  folly::Expected<std::pair<Buf, bool>, LocalErrorCode> read(
      StreamId id,
      size_t maxLen) override;

  void setReceiveWindow(StreamId, size_t /*recvWindowSize*/) override {}

  void setSendBuffer(StreamId, size_t /*maxUnacked*/, size_t /*maxUnsent*/)
      override {}

  /**
   * Set the initial flow control window for the connection.
   */
  void setTransportSettings(TransportSettings transportSettings) override;

  // If you don't set it, the default is Cubic
  void setCongestionControl(CongestionControlType type) override;

  virtual void setSupportedVersions(const std::vector<QuicVersion>& versions);

  /**
   * Set factory to create specific congestion controller instances
   * for a given connection.
   * Deletes current congestion controller instance, to create new controller
   * call setCongestionControl() or setTransportSettings().
   */
  virtual void setCongestionControllerFactory(
      std::shared_ptr<CongestionControllerFactory> factory);

  void addPacketProcessor(
      std::shared_ptr<PacketProcessor> packetProcessor) override;

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

  folly::Expected<folly::Unit, LocalErrorCode> setStreamPriority(
      StreamId id,
      Priority priority) override;

  /**
   * Sets the maximum pacing rate in Bytes per second to be used
   * if pacing is enabled.
   */
  folly::Expected<folly::Unit, LocalErrorCode> setMaxPacingRate(
      uint64_t maxRateBytesPerSec) override;

  void setThrottlingSignalProvider(
      std::shared_ptr<ThrottlingSignalProvider>) override;

  uint64_t maxWritableOnStream(const QuicStreamState&) const;

  [[nodiscard]] std::shared_ptr<QuicEventBase> getEventBase() const override;

  folly::Expected<StreamTransportInfo, LocalErrorCode> getStreamTransportInfo(
      StreamId id) const override;

  const QuicConnectionStateBase* getState() const override {
    return conn_.get();
  }

  const folly::SocketAddress& getPeerAddress() const override;

  const folly::SocketAddress& getOriginalPeerAddress() const override;

  Optional<std::string> getAppProtocol() const override;

  uint64_t getConnectionBufferAvailable() const override;

  folly::Expected<QuicSocketLite::FlowControlState, LocalErrorCode>
  getStreamFlowControl(StreamId id) const override;

  /**
   * Retrieve the transport settings
   */
  const TransportSettings& getTransportSettings() const override;

  [[nodiscard]] uint64_t maxWritableOnConn() const override;

  virtual void cancelAllAppCallbacks(const QuicError& error) noexcept;

  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::milliseconds timeout);

  class ExcessWriteTimeout : public QuicTimerCallback {
   public:
    ~ExcessWriteTimeout() override = default;

    explicit ExcessWriteTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->excessWriteTimeoutExpired();
    }

    void callbackCanceled() noexcept override {
      // Do nothing.
      return;
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  // Timeout functions
  class LossTimeout : public QuicTimerCallback {
   public:
    ~LossTimeout() override = default;

    explicit LossTimeout(QuicTransportBaseLite* transport)
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
    QuicTransportBaseLite* transport_;
  };

  class IdleTimeout : public QuicTimerCallback {
   public:
    ~IdleTimeout() override = default;

    explicit IdleTimeout(QuicTransportBaseLite* transport)
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
    QuicTransportBaseLite* transport_;
  };

  class KeepaliveTimeout : public QuicTimerCallback {
   public:
    ~KeepaliveTimeout() override = default;

    explicit KeepaliveTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->keepaliveTimeoutExpired();
    }
    void callbackCanceled() noexcept override {
      // Specifically do nothing since if we got canceled we shouldn't write.
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  class AckTimeout : public QuicTimerCallback {
   public:
    ~AckTimeout() override = default;

    explicit AckTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->ackTimeoutExpired();
    }

    virtual void callbackCanceled() noexcept override {
      // ignore. this usually means that the eventbase is dying, so we will be
      // canceled anyway
      return;
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  class PathValidationTimeout : public QuicTimerCallback {
   public:
    ~PathValidationTimeout() override = default;

    explicit PathValidationTimeout(QuicTransportBaseLite* transport)
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
    QuicTransportBaseLite* transport_;
  };

  class PingTimeout : public QuicTimerCallback {
   public:
    ~PingTimeout() override = default;

    explicit PingTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->pingTimeoutExpired();
    }

    void callbackCanceled() noexcept override {
      // ignore, as this happens only when event  base dies
      return;
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  // DrainTimeout is a bit different from other timeouts. It needs to hold a
  // shared_ptr to the transport, since if a DrainTimeout is scheduled,
  // transport cannot die.
  class DrainTimeout : public QuicTimerCallback {
   public:
    ~DrainTimeout() override = default;

    explicit DrainTimeout(QuicTransportBaseLite* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->drainTimeoutExpired();
    }

   private:
    QuicTransportBaseLite* transport_;
  };

  void scheduleLossTimeout(std::chrono::milliseconds timeout);

  void cancelLossTimeout();

  bool isLossTimeoutScheduled();

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

  /**
   * Cancel all byte event callbacks of all streams.
   */
  void cancelAllByteEventCallbacks() override;

  /**
   * Cancel all byte event callbacks of all streams of the given type.
   */
  void cancelByteEventCallbacks(const ByteEvent::Type type) override;

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

  StreamInitiator getStreamInitiator(StreamId stream) noexcept override;

  FOLLY_NODISCARD QuicConnectionStats getConnectionsStats() const override;

  /**
   * Returns a shared_ptr which can be used as a guard to keep this
   * object alive.
   */
  virtual std::shared_ptr<QuicTransportBaseLite> sharedGuard() = 0;

  void describe(std::ostream& os) const;

  /*
   * Creates buf accessor for use with in-place batch writer.
   */
  virtual void createBufAccessor(size_t /* capacity */) {}

  TransportInfo getTransportInfo() const override;

  const folly::SocketAddress& getLocalAddress() const override;

  using Observer = SocketObserverContainer::Observer;
  using ManagedObserver = SocketObserverContainer::ManagedObserver;

  /**
   * Adds an observer.
   *
   * If the observer is already added, this is a no-op.
   *
   * @param observer     Observer to add.
   * @return             Whether the observer was added (fails if no list).
   */
  bool addObserver(Observer* observer) {
    if (auto list = getSocketObserverContainer()) {
      list->addObserver(observer);
      return true;
    }
    return false;
  }

  /**
   * Adds an observer.
   *
   * If the observer is already added, this is a no-op.
   *
   * @param observer     Observer to add.
   * @return             Whether the observer was added (fails if no list).
   */
  bool addObserver(std::shared_ptr<Observer> observer) {
    if (auto list = getSocketObserverContainer()) {
      list->addObserver(std::move(observer));
      return true;
    }
    return false;
  }

  /**
   * Removes an observer.
   *
   * @param observer     Observer to remove.
   * @return             Whether the observer was found and removed.
   */
  bool removeObserver(Observer* observer) {
    if (auto list = getSocketObserverContainer()) {
      return list->removeObserver(observer);
    }
    return false;
  }

  /**
   * Removes an observer.
   *
   * @param observer     Observer to remove.
   * @return             Whether the observer was found and removed.
   */
  bool removeObserver(std::shared_ptr<Observer> observer) {
    if (auto list = getSocketObserverContainer()) {
      return list->removeObserver(std::move(observer));
    }
    return false;
  }

  /**
   * Get number of observers.
   *
   * @return             Number of observers.
   */
  [[nodiscard]] size_t numObservers() const {
    if (auto list = getSocketObserverContainer()) {
      return list->numObservers();
    }
    return 0;
  }

  /**
   * Returns list of attached observers.
   *
   * @return             List of observers.
   */
  std::vector<Observer*> getObservers() {
    if (auto list = getSocketObserverContainer()) {
      return list->getObservers();
    }
    return {};
  }

  /**
   * Returns list of attached observers that are of type T.
   *
   * @return             Attached observers of type T.
   */
  template <typename T = Observer>
  std::vector<T*> findObservers() {
    if (auto list = getSocketObserverContainer()) {
      return list->findObservers<T>();
    }
    return {};
  }

 protected:
  void setConnectionCallbackFromCtor(
      folly::MaybeManagedPtr<ConnectionCallback> callback);

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
   * Whether connection is paced will be decided by TransportSettings and
   * congection controller. When the connection is paced, this function writes
   * out a burst size of packets and let the writeLooper schedule a callback to
   * write another burst after a pacing interval if there are more data to
   * write. When the connection isn't paced, this function does a normal write.
   */
  void pacedWriteDataToSocket();

  /**
   * write data to socket
   *
   * At transport layer, this is the simplest form of write. It writes data
   * out to the network, and schedule necessary timers (ack, idle, loss). It is
   * both pacing oblivious and writeLooper oblivious. Caller needs to explicitly
   * invoke updateWriteLooper afterwards if that's desired.
   */
  void writeSocketData();

  void closeImpl(
      Optional<QuicError> error,
      bool drainConnection = true,
      bool sendCloseImmediately = true);

  void processCallbacksAfterNetworkData();

  void onSocketWritable() noexcept override;

  void handleNewStreamCallbacks(std::vector<StreamId>& newPeerStreams);
  void handleNewGroupedStreamCallbacks(std::vector<StreamId>& newPeerStreams);
  void handlePingCallbacks();
  void handleKnobCallbacks();
  void handleAckEventCallbacks();
  void handleCancelByteEventCallbacks();
  void invokeStreamsAvailableCallbacks();
  void handleDeliveryCallbacks();
  void handleStreamFlowControlUpdatedCallbacks(
      std::vector<StreamId>& streamStorage);
  void handleStreamStopSendingCallbacks();
  void handleConnWritable();
  void cleanupAckEventState();

  WriteQuicDataResult handleInitialWriteDataCommon(
      const ConnectionId& srcConnId,
      const ConnectionId& dstConnId,
      uint64_t packetLimit,
      const std::string& token = "");

  WriteQuicDataResult handleHandshakeWriteDataCommon(
      const ConnectionId& srcConnId,
      const ConnectionId& dstConnId,
      uint64_t packetLimit);

  void closeUdpSocket();

  folly::Expected<StreamId, LocalErrorCode> createStreamInternal(
      bool bidirectional,
      const OptionalIntegral<StreamGroupId>& streamGroupId = std::nullopt);

  void runOnEvbAsync(
      folly::Function<void(std::shared_ptr<QuicTransportBaseLite>)> func);

  void updateWriteLooper(bool thisIteration, bool runInline = false);
  void updateReadLooper();
  void updatePeekLooper();

  void maybeStopWriteLooperAndArmSocketWritableEvent();

  void checkForClosedStream();

  void cancelTimeout(QuicTimerCallback* callback);

  void excessWriteTimeoutExpired() noexcept;
  void lossTimeoutExpired() noexcept;
  void idleTimeoutExpired(bool drain) noexcept;
  void keepaliveTimeoutExpired() noexcept;
  void ackTimeoutExpired() noexcept;
  void pathValidationTimeoutExpired() noexcept;
  void drainTimeoutExpired() noexcept;
  void pingTimeoutExpired() noexcept;

  bool isTimeoutScheduled(QuicTimerCallback* callback) const;

  void invokeReadDataAndCallbacks(bool updateLoopersAndCheckForClosedStream);
  void invokePeekDataAndCallbacks();

  folly::Expected<folly::Unit, LocalErrorCode> setReadCallbackInternal(
      StreamId id,
      ReadCallback* cb,
      Optional<ApplicationErrorCode> err) noexcept;

  /**
   * The callback function for AsyncUDPSocket to provide the additional cmsgs
   * required by this QuicSocket's packet processors.
   */
  Optional<folly::SocketCmsgMap> getAdditionalCmsgsForAsyncUDPSocket();

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

  // Helpers to notify all registered observers about specific events during
  // socket write (if enabled in the observer's config).
  void notifyStartWritingFromAppRateLimited();
  void notifyPacketsWritten(
      const uint64_t /* numPacketsWritten */,
      const uint64_t /* numAckElicitingPacketsWritten */,
      const uint64_t /* numBytesWritten */);
  void notifyAppRateLimited();

  /**
   * Callback when we receive a transport knob
   */
  virtual void onTransportKnobs(Buf knobBlob);

  void processCallbacksAfterWriteData();

  void setIdleTimer();
  void scheduleAckTimeout();
  void schedulePathValidationTimeout();

  void resetConnectionCallbacks() {
    connSetupCallback_ = nullptr;
    connCallback_ = nullptr;
  }

  bool processCancelCode(const QuicError& cancelCode);

  void processConnectionSetupCallbacks(QuicError&& cancelCode);
  void processConnectionCallbacks(QuicError&& cancelCode);

  void updateCongestionControlSettings(
      const TransportSettings& transportSettings);

  void validateCongestionAndPacing(CongestionControlType& type);

  void updateSocketTosSettings(uint8_t dscpValue);

  /**
   * Helper function to validate that the number of ECN packet marks match the
   * expected value, depending on the ECN state of the connection.
   *
   * If ECN is enabled, this function validates it's working correctly. If ECN
   * is not enabled or has already failed validation, this function does
   * nothing.
   */
  void validateECNState();

  std::shared_ptr<QuicEventBase> evb_;
  std::unique_ptr<QuicAsyncUDPSocket> socket_;

  // TODO: This is silly. We need a better solution.
  // Uninitialied local address as a fallback answer when socket isn't bound.
  folly::SocketAddress localFallbackAddress;

  CloseState closeState_{CloseState::OPEN};

  folly::MaybeManagedPtr<ConnectionSetupCallback> connSetupCallback_{nullptr};
  folly::MaybeManagedPtr<ConnectionCallback> connCallback_{nullptr};
  PingCallback* pingCallback_{nullptr};
  // A flag telling transport if the new onConnectionEnd(error) cb must be used.
  bool useConnectionEndWithErrorCallback_{false};

  bool transportReadyNotified_{false};

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

  DatagramCallback* datagramCallback_{nullptr};

  folly::F14FastMap<StreamId, ReadCallbackData> readCallbacks_;
  folly::F14FastMap<StreamId, PeekCallbackData> peekCallbacks_;

  ConnectionWriteCallback* connWriteCallback_{nullptr};
  std::map<StreamId, StreamWriteCallback*> pendingWriteCallbacks_;

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

  ByteEventMap deliveryCallbacks_;
  ByteEventMap txCallbacks_;

  /**
   * Checks the idle timer on write events, and if it's past the idle timeout,
   * calls the timer finctions.
   */
  void checkIdleTimer(TimePoint now);
  struct IdleTimeoutCheck {
    std::chrono::milliseconds idleTimeoutMs{0};
    Optional<TimePoint> lastTimeIdleTimeoutScheduled_;
    bool forcedIdleTimeoutScheduled_{false};
  };
  IdleTimeoutCheck idleTimeoutCheck_;

  LossTimeout lossTimeout_;
  ExcessWriteTimeout excessWriteTimeout_;
  IdleTimeout idleTimeout_;
  KeepaliveTimeout keepaliveTimeout_;
  AckTimeout ackTimeout_;
  PathValidationTimeout pathValidationTimeout_;
  DrainTimeout drainTimeout_;
  PingTimeout pingTimeout_;

  FunctionLooper::Ptr writeLooper_;
  FunctionLooper::Ptr readLooper_;
  FunctionLooper::Ptr peekLooper_;

  Optional<std::string> exceptionCloseWhat_;

  std::
      unique_ptr<QuicConnectionStateBase, folly::DelayedDestruction::Destructor>
          conn_;

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
    explicit WrappedSocketObserverContainer(QuicSocketLite* socket)
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

 private:
  /**
   * Helper functions to handle new streams.
   */
  void handleNewStreams(std::vector<StreamId>& newPeerStreams);
  void handleNewGroupedStreams(std::vector<StreamId>& newPeerStreams);

  /**
   * Helper to log new stream event to observer.
   */
  void logStreamOpenEvent(StreamId streamId);

  bool hasDeliveryCallbacksToCall(
      StreamId streamId,
      uint64_t maxOffsetToDeliver) const;

  /**
   * Helper function to collect prewrite requests from the PacketProcessors
   * Currently this collects cmsgs to be written. The Cmsgs will be stored in
   * the connection state and passed to AsyncUDPSocket in the next
   * additionalCmsgs callback
   */
  void updatePacketProcessorsPrewriteRequests();
};

std::ostream& operator<<(std::ostream& os, const QuicTransportBaseLite& qt);

} // namespace quic
