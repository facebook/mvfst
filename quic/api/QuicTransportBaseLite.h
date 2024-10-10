/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocketLite.h>

namespace quic {

enum class CloseState { OPEN, GRACEFUL_CLOSING, CLOSED };

class QuicTransportBaseLite : virtual public QuicSocketLite {
 public:
  QuicTransportBaseLite(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      bool useConnectionEndWithErrorCallback)
      : evb_(evb),
        socket_(std::move(socket)),
        useConnectionEndWithErrorCallback_(useConnectionEndWithErrorCallback) {}

  /**
   * Invoked when we have to write some data to the wire.
   * The subclass may use this to start writing data to the socket.
   * It may also throw an exception in case of an error in which case the
   * connection will be closed.
   */
  virtual void writeData() = 0;

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

  virtual void scheduleLossTimeout(std::chrono::milliseconds /* timeout */) {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }

  virtual void cancelLossTimeout() {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }

  virtual bool isLossTimeoutScheduled() {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
    return false;
  }

 protected:
  /**
   * write data to socket
   *
   * At transport layer, this is the simplest form of write. It writes data
   * out to the network, and schedule necessary timers (ack, idle, loss). It is
   * both pacing oblivious and writeLooper oblivious. Caller needs to explicitly
   * invoke updateWriteLooper afterwards if that's desired.
   */
  void writeSocketData();

  virtual void updateWriteLooper(
      bool /* thisIteration */,
      bool /* runInline */ = false) {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }

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

  virtual void setIdleTimer() {
    // TODO: Fill this in from QuicTransportBase and remove the "virtual"
    // qualifier
  }
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

} // namespace quic
