/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocketLite.h>
#include <quic/common/FunctionLooper.h>

namespace quic {

enum class CloseState { OPEN, GRACEFUL_CLOSING, CLOSED };

class QuicTransportBaseLite : virtual public QuicSocketLite,
                              QuicAsyncUDPSocket::WriteCallback {
 public:
  QuicTransportBaseLite(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      bool useConnectionEndWithErrorCallback)
      : evb_(evb),
        socket_(std::move(socket)),
        useConnectionEndWithErrorCallback_(useConnectionEndWithErrorCallback),
        lossTimeout_(this),
        excessWriteTimeout_(this),
        idleTimeout_(this),
        keepaliveTimeout_(this),
        writeLooper_(new FunctionLooper(
            evb_,
            [this]() { pacedWriteDataToSocket(); },
            LooperType::WriteLooper)),
        readLooper_(new FunctionLooper(
            evb_,
            [this]() { invokeReadDataAndCallbacks(); },
            LooperType::ReadLooper)),
        peekLooper_(new FunctionLooper(
            evb_,
            [this]() { invokePeekDataAndCallbacks(); },
            LooperType::PeekLooper)) {}

  /**
   * Invoked when we have to write some data to the wire.
   * The subclass may use this to start writing data to the socket.
   * It may also throw an exception in case of an error in which case the
   * connection will be closed.
   */
  virtual void writeData() = 0;

  folly::Expected<folly::Unit, LocalErrorCode> notifyPendingWriteOnStream(
      StreamId id,
      QuicSocketLite::WriteCallback* wcb) override;

  folly::Expected<folly::Unit, LocalErrorCode> notifyPendingWriteOnConnection(
      QuicSocketLite::WriteCallback* wcb) override;

  folly::Expected<folly::Unit, LocalErrorCode> unregisterStreamWriteCallback(
      StreamId id) override;

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

  void setReceiveWindow(StreamId, size_t /*recvWindowSize*/) override {}

  void setSendBuffer(StreamId, size_t /*maxUnacked*/, size_t /*maxUnsent*/)
      override {}

  uint64_t maxWritableOnStream(const QuicStreamState&) const;

  [[nodiscard]] std::shared_ptr<QuicEventBase> getEventBase() const override;

  folly::Expected<StreamTransportInfo, LocalErrorCode> getStreamTransportInfo(
      StreamId id) const override;

  const QuicConnectionStateBase* getState() const override {
    return conn_.get();
  }

  const folly::SocketAddress& getPeerAddress() const override;

  Optional<std::string> getAppProtocol() const override;

  uint64_t getConnectionBufferAvailable() const override;

  folly::Expected<QuicSocketLite::FlowControlState, LocalErrorCode>
  getStreamFlowControl(StreamId id) const override;

  [[nodiscard]] uint64_t maxWritableOnConn() const override;

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

  void scheduleLossTimeout(std::chrono::milliseconds timeout);

  void cancelLossTimeout();

  bool isLossTimeoutScheduled();

  /**
   * Returns a shared_ptr which can be used as a guard to keep this
   * object alive.
   */
  virtual std::shared_ptr<QuicTransportBaseLite> sharedGuard() = 0;

  void describe(std::ostream& os) const;

 protected:
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

  virtual void closeImpl(
      Optional<QuicError> /* error */,
      bool /* drainConnection */ = true,
      bool /* sendCloseImmediately */ = true) {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }

  void runOnEvbAsync(
      folly::Function<void(std::shared_ptr<QuicTransportBaseLite>)> func);

  void updateWriteLooper(bool thisIteration, bool runInline = false);
  void updateReadLooper();
  void updatePeekLooper();

  void maybeStopWriteLooperAndArmSocketWritableEvent();

  virtual void checkForClosedStream() {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }

  void cancelTimeout(QuicTimerCallback* callback);

  void excessWriteTimeoutExpired() noexcept;
  void lossTimeoutExpired() noexcept;
  void idleTimeoutExpired(bool drain) noexcept;
  void keepaliveTimeoutExpired() noexcept;

  bool isTimeoutScheduled(QuicTimerCallback* callback) const;

  void invokeReadDataAndCallbacks();
  void invokePeekDataAndCallbacks();

  // Helpers to notify all registered observers about specific events during
  // socket write (if enabled in the observer's config).
  virtual void notifyStartWritingFromAppRateLimited() {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }
  virtual void notifyPacketsWritten(
      const uint64_t /* numPacketsWritten */,
      const uint64_t /* numAckElicitingPacketsWritten */,
      const uint64_t /* numBytesWritten */) {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }
  virtual void notifyAppRateLimited() {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }

  void processCallbacksAfterWriteData();

  void setIdleTimer();
  virtual void scheduleAckTimeout() {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }
  virtual void schedulePathValidationTimeout() {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }

  void resetConnectionCallbacks() {
    connSetupCallback_ = nullptr;
    connCallback_ = nullptr;
  }

  bool processCancelCode(const QuicError& cancelCode);

  void processConnectionSetupCallbacks(QuicError&& cancelCode);
  void processConnectionCallbacks(QuicError&& cancelCode);

  std::shared_ptr<QuicEventBase> evb_;
  std::unique_ptr<QuicAsyncUDPSocket> socket_;

  CloseState closeState_{CloseState::OPEN};

  folly::MaybeManagedPtr<ConnectionSetupCallback> connSetupCallback_{nullptr};
  folly::MaybeManagedPtr<ConnectionCallback> connCallback_{nullptr};
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

  std::map<StreamId, QuicSocketLite::WriteCallback*> pendingWriteCallbacks_;
  QuicSocketLite::WriteCallback* connWriteCallback_{nullptr};

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

  FunctionLooper::Ptr writeLooper_;
  FunctionLooper::Ptr readLooper_;
  FunctionLooper::Ptr peekLooper_;

  Optional<std::string> exceptionCloseWhat_;

  std::
      unique_ptr<QuicConnectionStateBase, folly::DelayedDestruction::Destructor>
          conn_;

 private:
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
