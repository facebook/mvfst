/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/api/QuicTransportBase.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>

namespace quic {

class TestQuicTransport
    : public QuicTransportBase,
      public std::enable_shared_from_this<TestQuicTransport> {
 public:
  TestQuicTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      ConnectionCallback& cb)
      : QuicTransportBase(evb, std::move(socket)) {
    setConnectionCallback(&cb);
    conn_.reset(new QuicServerConnectionState(
        FizzServerQuicHandshakeContext::Builder().build()));
    conn_->clientConnectionId = ConnectionId({9, 8, 7, 6});
    conn_->serverConnectionId = ConnectionId({1, 2, 3, 4});
    conn_->version = QuicVersion::MVFST;
    aead = test::createNoOpAead();
    headerCipher = test::createNoOpHeaderCipher();
  }

  ~TestQuicTransport() override {
    // we need to call close in the derived class.
    connCallback_ = nullptr;
    closeImpl(
        std::make_pair(
            QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
            std::string("shutdown")),
        false);
  }

  QuicVersion getVersion() {
    auto& conn = getConnectionState();
    return conn.version.value_or(*conn.originalVersion);
  }

  void updateWriteLooper(bool thisIteration) {
    QuicTransportBase::updateWriteLooper(thisIteration);
  }

  void pacedWrite(bool fromTimer) {
    pacedWriteDataToSocket(fromTimer);
  }

  bool isPacingScheduled() {
    return writeLooper_->isScheduled();
  }

  void onReadData(
      const folly::SocketAddress& /*peer*/,
      NetworkDataSingle&& /*networkData*/) noexcept override {}

  void writeData() override {
    if (closed) {
      return;
    }
    writeQuicDataToSocket(
        *socket_,
        *conn_,
        *conn_->clientConnectionId,
        *conn_->serverConnectionId,
        *aead,
        *headerCipher,
        getVersion(),
        (isConnectionPaced(*conn_)
             ? conn_->pacer->updateAndGetWriteBatchSize(Clock::now())
             : conn_->transportSettings.writeConnectionDataPacketsLimit));
  }

  void closeTransport() override {
    closed = true;
  }

  bool hasWriteCipher() const override {
    return true;
  }

  std::shared_ptr<QuicTransportBase> sharedGuard() override {
    return shared_from_this();
  }

  void unbindConnection() override {}

  QuicServerConnectionState& getConnectionState() {
    return *dynamic_cast<QuicServerConnectionState*>(conn_.get());
  }

  auto getAckTimeout() {
    return &ackTimeout_;
  }

  auto& getPathValidationTimeout() {
    return pathValidationTimeout_;
  }

  auto& lossTimeout() {
    return lossTimeout_;
  }

  auto& idleTimeout() {
    return idleTimeout_;
  }

  CloseState closeState() {
    return closeState_;
  }

  folly::HHWheelTimer* getTimer() {
    return &getEventBase()->timer();
  }

  void drainImmediately() {
    drainTimeoutExpired();
  }

  void setIdleTimerNow() {
    setIdleTimer();
  }

  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
  bool closed{false};
};

} // namespace quic
