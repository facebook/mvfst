/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/protocol/DefaultCertificateVerifier.h>
#include <fizz/server/FizzServer.h>
#include <fizz/server/FizzServerContext.h>
#include <fizz/server/ServerProtocol.h>

#include <folly/io/IOBufQueue.h>
#include <folly/io/async/DelayedDestruction.h>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/server/handshake/AppToken.h>
#include <quic/server/handshake/ServerTransportParametersExtension.h>
#include <quic/state/StateData.h>

namespace quic {

/**
 * ServerHandshake abstracts details of the TLS 1.3 fizz crypto handshake. The
 * TLS handshake can be async, so ServerHandshake provides an API to deal with
 * the async handshake to work well with the re-entrancy requirements of the
 * QUIC state machine. The use of this is meant to be the following:
 *
 * handshake->doHandshake(newData); // This can throw an exception.
 * auto writeBytes = handshake->getWriteBytes();
 * auto hanshakeState = handshake->getHandshakeState();
 * writeBytesToSocket(writeBytes);
 *
 * If the handshake is async, then data will be returned async
 *
 * void onCryptoEventAvailable() noexcept {
 *   try {
 *     auto writeBytes = handshake->getWriteBytes();
 *     auto hanshakeState = handshake->getHandshakeState();
 *     writeBytesToSocket(writeBytes);
 *   } catch (const QuicTransportException& ex) {
 *     ....
 *   }
 *  }
 * }
 */

class ServerHandshake : public Handshake {
 public:
  class HandshakeCallback {
   public:
    virtual ~HandshakeCallback() = default;

    virtual void onCryptoEventAvailable() noexcept = 0;
  };

  /**
   * The 3 phases are as follows:
   * Handshake: We can only write crypto data with handshake keys
   * KeysDerived: Write crypto data with handshake keys and 1-rtt data with
   * 1-rtt keys.
   * Established: Write all data with 1-rtt keys.
   */
  enum class Phase { Handshake, KeysDerived, Established };

  explicit ServerHandshake(QuicCryptoState& cryptoState);

  /**
   * Starts accepting the TLS connection.
   */
  virtual void accept(
      std::shared_ptr<ServerTransportParametersExtension> transportParams);

  /**
   * Initialize the handshake with the executor and the callback.
   * The class will clone the context, so the same context will not be used
   * directly. To get the real context used, call getContext() after invoking
   * initialize.
   */
  virtual void initialize(
      folly::Executor* executor,
      std::shared_ptr<const fizz::server::FizzServerContext> context,
      HandshakeCallback* callback,
      std::unique_ptr<fizz::server::AppTokenValidator> validator = nullptr);

  /**
   * Performs the handshake, after a handshake you should check whether or
   * not an event is available.
   */
  virtual void doHandshake(
      std::unique_ptr<folly::IOBuf> data,
      EncryptionLevel encryptionLevel);

  /**
   * Writes a session ticket on the connection.
   */
  virtual void writeNewSessionTicket(const AppToken& appToken);

  /**
   * An edge triggered API to get the handshakeWriteCipher. Once you receive the
   * write cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getHandshakeWriteCipher();

  /**
   * An edge triggered API to get the handshakeReadCipher. Once you receive the
   * write cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getHandshakeReadCipher();

  /**
   * An edge triggered API to get the oneRttWriteCipher. Once you receive the
   * write cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getOneRttWriteCipher();

  /**
   * An edge triggered API to get the oneRttReadCipher. Once you receive the
   * read cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getOneRttReadCipher();

  /**
   * An edge triggered API to get the zeroRttReadCipher. Once you receive the
   * zero rtt read cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getZeroRttReadCipher();

  /**
   * An edge triggered API to get the one rtt read header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getOneRttReadHeaderCipher();

  /**
   * An edge triggered API to get the one rtt write header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getOneRttWriteHeaderCipher();

  /**
   * An edge triggered API to get the handshake rtt read header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getHandshakeReadHeaderCipher();

  /**
   * An edge triggered API to get the handshake rtt write header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getHandshakeWriteHeaderCipher();

  /**
   * An edge triggered API to get the zero rtt header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getZeroRttReadHeaderCipher();

  /**
   * The application will not get any more callbacks from the handshake layer
   * after this method returns.
   */
  virtual void cancel();

  virtual Phase getPhase() const;

  /**
   * Returns the negotiated transport parameters from the client.
   */
  virtual folly::Optional<ClientTransportParameters> getClientTransportParams();

  /**
   * Returns whether all the events that the handshake needs are complete.
   */
  bool isHandshakeDone();

  /**
   * Returns the fizz server state.
   */
  const fizz::server::State& getState() const;

  /**
   * Returns the context used by the ServerHandshake.
   */
  const std::shared_ptr<const fizz::server::FizzServerContext> getContext()
      const;

  /**
   * Retuns the negotiated ALPN from the handshake.
   */
  const folly::Optional<std::string>& getApplicationProtocol() const override;

  class ActionMoveVisitor : public boost::static_visitor<> {
   public:
    explicit ActionMoveVisitor(ServerHandshake& server);

    void operator()(fizz::DeliverAppData&);
    void operator()(fizz::WriteToSocket& write);
    void operator()(fizz::server::ReportEarlyHandshakeSuccess&);
    void operator()(fizz::server::ReportHandshakeSuccess&);
    void operator()(fizz::ReportError& err);
    void operator()(fizz::WaitForData&);
    void operator()(fizz::server::MutateState& mutator);
    void operator()(fizz::server::AttemptVersionFallback&);
    void operator()(fizz::SecretAvailable&);
    void operator()(fizz::EndOfData&);

   private:
    ServerHandshake& server_;
  };

  virtual ~ServerHandshake() = default;

  void onError(std::pair<std::string, TransportErrorCode> error);

  void onWriteData(fizz::WriteToSocket& write);

  void onHandshakeDone();

  /**
   * Used to schedule actions to process which might be async.
   */
  void addProcessingActions(fizz::server::AsyncActions actions);

  /**
   * Start an async or synchronous action, once the async guard is acquired.
   */
  void startActions(fizz::server::AsyncActions actions);

  /**
   * Run the actions once they have been completed.
   */
  void processActions(
      fizz::server::ServerStateMachine::CompletedActions actions);

  /**
   * Process any pending events that might have been queued up because there
   * was an async action pending.
   */
  void processPendingEvents();

  fizz::server::State state_;
  fizz::server::ServerStateMachine machine_;
  folly::Optional<folly::DelayedDestruction::DestructorGuard> actionGuard_;
  folly::Executor* executor_;
  std::shared_ptr<const fizz::server::FizzServerContext> context_;
  using PendingEvent = boost::variant<fizz::WriteNewSessionTicket>;
  std::deque<PendingEvent> pendingEvents_;

  QuicCryptoState& cryptoState_;
  ActionMoveVisitor visitor_;
  bool inProcessPendingEvents_{false};
  bool waitForData_{false};

  folly::IOBufQueue initialReadBuf_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue handshakeReadBuf_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue appDataReadBuf_{folly::IOBufQueue::cacheChainLength()};

  HandshakeCallback* callback_{nullptr};
  folly::Optional<std::pair<std::string, TransportErrorCode>> error_;

  std::unique_ptr<fizz::Aead> handshakeReadCipher_;
  std::unique_ptr<fizz::Aead> handshakeWriteCipher_;
  std::unique_ptr<fizz::Aead> oneRttReadCipher_;
  std::unique_ptr<fizz::Aead> oneRttWriteCipher_;
  std::unique_ptr<fizz::Aead> zeroRttReadCipher_;

  std::unique_ptr<PacketNumberCipher> oneRttReadHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> handshakeReadHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> handshakeWriteHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> zeroRttReadHeaderCipher_;

  bool inHandshakeStack_{false};
  bool handshakeDone_{false};
  bool handshakeEventAvailable_{false};

  Phase phase_{Phase::Handshake};

  std::shared_ptr<ServerTransportParametersExtension> transportParams_;
}; // namespace quic
} // namespace quic
