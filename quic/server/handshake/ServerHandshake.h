/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/DefaultCertificateVerifier.h>
#include <fizz/server/FizzServer.h>
#include <fizz/server/FizzServerContext.h>

#include <folly/io/IOBufQueue.h>
#include <folly/io/async/DelayedDestruction.h>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/handshake/CryptoFactory.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/server/handshake/AppToken.h>
#include <quic/server/handshake/ServerTransportParametersExtension.h>
#include <quic/state/StateData.h>

namespace quic {

// struct QuicConnectionStateBase;

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

  explicit ServerHandshake(QuicConnectionStateBase* conn);

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
   * Returns a reference to the CryptoFactory used internally.
   */
  virtual const CryptoFactory& getCryptoFactory() const = 0;

  /**
   * An edge triggered API to get the handshakeReadCipher. Once you receive the
   * write cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getHandshakeReadCipher();

  /**
   * An edge triggered API to get the first oneRttWriteCipher. Once you receive
   * the write cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getFirstOneRttWriteCipher();

  /**
   * An API to get oneRttWriteCiphers on key rotation. Each call will return a
   * one rtt write cipher using the current traffic secret and advance the
   * traffic secret.
   */
  std::unique_ptr<Aead> getNextOneRttWriteCipher() override;

  /**
   * An API to get oneRttReadCiphers. Each call will generate a one rtt
   * read cipher using the current traffic secret and advance the traffic
   * secret.
   */
  std::unique_ptr<Aead> getFirstOneRttReadCipher();

  /**
   * An API to get oneRttReadCiphers on key rotation. Each call will return a
   * one rtt read cipher using the current traffic secret and advance the
   * traffic secret.
   */
  std::unique_ptr<Aead> getNextOneRttReadCipher() override;

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
   * Returns the exporter master secret from the handshake.
   */
  folly::Optional<std::vector<uint8_t>> getExportedKeyingMaterial(
      const std::string& label,
      const folly::Optional<folly::ByteRange>& context,
      uint16_t keyLength) override;

  /**
   * Returns the negotiated ALPN from the handshake.
   */
  const folly::Optional<std::string>& getApplicationProtocol() const override;

  /**
   * Given secret_n, returns secret_n+1 to be used for generating the next Aead
   * on key updates.
   */
  virtual Buf getNextTrafficSecret(folly::ByteRange secret) const = 0;

  ~ServerHandshake() override = default;

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
  class ActionMoveVisitor;
  void processActions(
      fizz::server::ServerStateMachine::CompletedActions actions);

  /**
   * Process any pending events that might have been queued up because there
   * was an async action pending.
   */
  void processPendingEvents();

  /**
   * Returns the AppToken seen in session ticket if the session was resumed.
   */
  const folly::Optional<Buf>& getAppToken() const;

 protected:
  Phase phase_{Phase::Handshake};

  enum class CipherKind {
    HandshakeRead,
    HandshakeWrite,
    OneRttRead,
    OneRttWrite,
    ZeroRttRead,
  };

  void computeCiphers(CipherKind kind, folly::ByteRange secret);

  fizz::server::State state_;
  fizz::server::ServerStateMachine machine_;
  QuicConnectionStateBase* conn_;
  folly::DelayedDestruction::DestructorGuard actionGuard_;
  folly::Executor* executor_;

  QuicCryptoState& cryptoState_;
  bool inProcessPendingEvents_{false};
  bool waitForData_{false};

  folly::IOBufQueue initialReadBuf_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue handshakeReadBuf_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue appDataReadBuf_{folly::IOBufQueue::cacheChainLength()};

  HandshakeCallback* callback_{nullptr};
  folly::Optional<std::pair<std::string, TransportErrorCode>> error_;

  std::unique_ptr<Aead> handshakeReadCipher_;
  std::unique_ptr<Aead> oneRttReadCipher_;
  std::unique_ptr<Aead> oneRttWriteCipher_;
  std::unique_ptr<Aead> zeroRttReadCipher_;

  Buf readTrafficSecret_;
  Buf writeTrafficSecret_;

  // This variable is incremented every time a read traffic secret is rotated,
  // and decremented for the write secret. Its value should be
  // between -1 and 1. A value outside of this range indicates that the
  // transport's read and write ciphers are likely out of sync.
  int trafficSecretSync_{0};

  std::unique_ptr<PacketNumberCipher> oneRttReadHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> handshakeReadHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> zeroRttReadHeaderCipher_;

  bool inHandshakeStack_{false};
  bool handshakeDone_{false};
  bool handshakeEventAvailable_{false};

  std::shared_ptr<ServerTransportParametersExtension> transportParams_;

 private:
  virtual void initializeImpl(
      HandshakeCallback* callback,
      std::unique_ptr<fizz::server::AppTokenValidator> validator) = 0;

  virtual EncryptionLevel getReadRecordLayerEncryptionLevel() = 0;
  virtual void processSocketData(folly::IOBufQueue& queue) = 0;
  virtual std::unique_ptr<Aead> buildAead(folly::ByteRange secret) = 0;
  virtual std::unique_ptr<PacketNumberCipher> buildHeaderCipher(
      folly::ByteRange secret) = 0;

  virtual void processAccept() = 0;
  /*
   * Process a pending crypto event, if one was present. Returns if there was
   * a pending event.
   */
  virtual bool processPendingCryptoEvent() = 0;
  virtual void writeNewSessionTicketToCrypto(const AppToken& appToken) = 0;
}; // namespace quic

} // namespace quic
