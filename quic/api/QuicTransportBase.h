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
                          virtual public QuicTransportBaseLite {
 public:
  QuicTransportBase(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      bool useConnectionEndWithErrorCallback = false);

  ~QuicTransportBase() override;

  void setPacingTimer(QuicTimer::SharedPtr pacingTimer) noexcept;

  [[nodiscard]] Optional<ConnectionId> getClientConnectionId() const override;

  [[nodiscard]] Optional<ConnectionId> getServerConnectionId() const override;

  [[nodiscard]] Optional<ConnectionId> getClientChosenDestConnectionId()
      const override;

  // QuicSocket interface
  [[nodiscard]] bool replaySafe() const override;

  void closeGracefully() override;

  [[nodiscard]] quic::Expected<size_t, LocalErrorCode> getStreamReadOffset(
      StreamId id) const override;
  [[nodiscard]] quic::Expected<size_t, LocalErrorCode> getStreamWriteOffset(
      StreamId id) const override;
  [[nodiscard]] quic::Expected<size_t, LocalErrorCode>
  getStreamWriteBufferedBytes(StreamId id) const override;

  [[nodiscard]] quic::Expected<QuicSocket::FlowControlState, LocalErrorCode>
  getConnectionFlowControl() const override;

  [[nodiscard]] quic::Expected<uint64_t, LocalErrorCode> getMaxWritableOnStream(
      StreamId id) const override;

  quic::Expected<void, LocalErrorCode> setConnectionFlowControlWindow(
      uint64_t windowSize) override;

  quic::Expected<void, LocalErrorCode> setStreamFlowControlWindow(
      StreamId id,
      uint64_t windowSize) override;

  void unsetAllReadCallbacks() override;
  void unsetAllPeekCallbacks() override;
  void unsetAllDeliveryCallbacks() override;
  quic::Expected<void, LocalErrorCode> pauseRead(StreamId id) override;
  quic::Expected<void, LocalErrorCode> resumeRead(StreamId id) override;

  quic::Expected<void, LocalErrorCode> setPeekCallback(
      StreamId id,
      PeekCallback* cb) override;

  quic::Expected<void, LocalErrorCode> pausePeek(StreamId id) override;
  quic::Expected<void, LocalErrorCode> resumePeek(StreamId id) override;

  quic::Expected<void, LocalErrorCode> peek(
      StreamId id,
      const std::function<void(StreamId id, const folly::Range<PeekIterator>&)>&
          peekCallback) override;

  quic::Expected<void, LocalErrorCode> consume(StreamId id, size_t amount)
      override;

  quic::Expected<void, std::pair<LocalErrorCode, Optional<uint64_t>>>
  consume(StreamId id, uint64_t offset, size_t amount) override;

  bool isClientStream(StreamId stream) noexcept override;
  bool isServerStream(StreamId stream) noexcept override;
  StreamDirectionality getStreamDirectionality(
      StreamId stream) noexcept override;

  quic::Expected<void, LocalErrorCode> maybeResetStreamFromReadError(
      StreamId id,
      QuicErrorCode error) override;

  quic::Expected<void, LocalErrorCode> setPingCallback(
      PingCallback* cb) override;

  void sendPing(std::chrono::milliseconds pingTimeout) override;

  [[nodiscard]] const QuicConnectionStateBase* getState() const override {
    return conn_.get();
  }

  virtual void setAckRxTimestampsEnabled(bool enableAckRxTimestamps);

  void setEarlyDataAppParamsFunctions(
      std::function<bool(const Optional<std::string>&, const BufPtr&)>
          validator,
      std::function<BufPtr()> getter) final;

  bool isDetachable() override;

  void detachEventBase() override;

  void attachEventBase(std::shared_ptr<QuicEventBase> evb) override;

  // Subclass API.

  quic::Expected<PriorityQueue::Priority, LocalErrorCode> getStreamPriority(
      StreamId id) override;

  /**
   * Register a callback to be invoked when the stream offset was transmitted.
   *
   * Currently, an offset is considered "transmitted" if it has been written to
   * to the underlying UDP socket, indicating that it has passed through
   * congestion control and pacing. In the future, this callback may be
   * triggered by socket/NIC software or hardware timestamps.
   */
  quic::Expected<void, LocalErrorCode> registerTxCallback(
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

  void setLoopDetectorCallback(std::shared_ptr<LoopDetectorCallback> callback) {
    conn_->loopDetectorCallback = std::move(callback);
  }

  /**
   * Set the read callback for Datagrams
   */
  quic::Expected<void, LocalErrorCode> setDatagramCallback(
      DatagramCallback* cb) override;

  /**
   * Returns the maximum allowed Datagram payload size.
   * 0 means Datagram is not supported
   */
  [[nodiscard]] uint16_t getDatagramSizeLimit() const override;

  /**
   * Writes a Datagram frame. If buf is larger than the size limit returned by
   * getDatagramSizeLimit(), or if the write buffer is full, buf will simply be
   * dropped, and a LocalErrorCode will be returned to caller.
   */
  quic::Expected<void, LocalErrorCode> writeDatagram(BufPtr buf) override;

  /**
   * Returns the currently available received Datagrams.
   * Returns all datagrams if atMost is 0.
   */
  quic::Expected<std::vector<ReadDatagram>, LocalErrorCode> readDatagrams(
      size_t atMost = 0) override;

  /**
   * Returns the currently available received Datagram IOBufs.
   * Returns all datagrams if atMost is 0.
   */
  quic::Expected<std::vector<BufPtr>, LocalErrorCode> readDatagramBufs(
      size_t atMost = 0) override;

  /**
   * This is used in conjunction with reliable resets. When we send data on a
   * stream and want to mark which offset will constitute the reliable size in a
   * future call to resetStreamReliably, we call this function. This function
   * can potentially be called multiple times on a stream to advance the offset,
   * but it is an error to call it after sending a reset.
   */
  quic::Expected<void, LocalErrorCode> updateReliableDeliveryCheckpoint(
      StreamId id) override;

  /**
   * Send a reliable reset to the peer. The reliable size sent to the peer is
   * determined by when checkpoint(streamId) was last called.
   */
  quic::Expected<void, LocalErrorCode> resetStreamReliably(
      StreamId id,
      ApplicationErrorCode error) override;

  /**
   * Set control messages to be sent for socket_ write, note that it's for this
   * specific transport and does not change the other sockets sharing the same
   * fd.
   */
  void setCmsgs(const folly::SocketCmsgMap& options);

  void appendCmsgs(const folly::SocketCmsgMap& options);

  /**
   * Sets whether retransmissions are disabled for a specific stream.
   */
  quic::Expected<void, LocalErrorCode> setStreamRetransmissionDisabled(
      StreamId id,
      bool disabled) noexcept override;

  [[nodiscard]] QuicAsyncUDPSocket* getUdpSocket() const {
    return socket_.get();
  }

 protected:
  quic::Expected<void, LocalErrorCode> pauseOrResumeRead(
      StreamId id,
      bool resume);
  quic::Expected<void, LocalErrorCode> pauseOrResumePeek(
      StreamId id,
      bool resume);
  quic::Expected<void, LocalErrorCode> setPeekCallbackInternal(
      StreamId id,
      PeekCallback* cb) noexcept;

  void schedulePingTimeout(
      PingCallback* callback,
      std::chrono::milliseconds pingTimeout);

  void updatePeekLooper() override;
  void invokePeekDataAndCallbacks() override;
  void handlePingCallbacks() override;
  void cleanupPeekPingDatagramResources() override;
  void cancelPeekPingDatagramCallbacks(const QuicError& err) override;
  bool hasPeekCallback(StreamId id) override;
  void invokeDatagramCallbackIfSet() override;
  void pingTimeoutExpired() noexcept;

  class PingTimeout : public QuicTimerCallback {
   public:
    ~PingTimeout() override = default;

    explicit PingTimeout(QuicTransportBase* transport)
        : transport_(transport) {}

    void timeoutExpired() noexcept override {
      transport_->pingTimeoutExpired();
    }

    void callbackCanceled() noexcept override {
      // ignore, as this happens only when event base dies
      return;
    }

   private:
    QuicTransportBase* transport_;
  };

  struct PeekCallbackData {
    PeekCallback* peekCb;
    bool resumed{true};

    PeekCallbackData(PeekCallback* peekCallback) : peekCb(peekCallback) {}
  };

  PingCallback* pingCallback_{nullptr};
  PingTimeout pingTimeout_;
  DatagramCallback* datagramCallback_{nullptr};
  UnorderedMap<StreamId, PeekCallbackData> peekCallbacks_;
  FunctionLooper::Ptr peekLooper_;

  bool handshakeDoneNotified_{false};
};

} // namespace quic
