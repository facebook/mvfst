/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/client/ClientProtocol.h>
#include <fizz/client/EarlyDataRejectionPolicy.h>
#include <fizz/client/FizzClientContext.h>
#include <fizz/client/PskCache.h>
#include <fizz/protocol/DefaultCertificateVerifier.h>

#include <folly/io/IOBufQueue.h>
#include <folly/io/async/DelayedDestruction.h>

#include <folly/ExceptionWrapper.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/client/handshake/QuicPskCache.h>
#include <quic/handshake/CryptoFactory.h>
#include <quic/handshake/HandshakeLayer.h>
#include <quic/state/StateData.h>

namespace quic {

class ClientHandshake : public Handshake {
 public:
  class HandshakeCallback {
   public:
    virtual ~HandshakeCallback() = default;

    virtual void onNewCachedPsk(fizz::client::NewCachedPsk&) noexcept = 0;
  };

  enum class Phase { Initial, Handshake, OneRttKeysDerived, Established };

  explicit ClientHandshake(QuicCryptoState& cryptoState);

  /**
   * Initiate the handshake with the supplied parameters.
   */
  virtual void connect(
      std::shared_ptr<const fizz::client::FizzClientContext> context,
      std::shared_ptr<const fizz::CertificateVerifier> verifier,
      folly::Optional<std::string> hostname,
      folly::Optional<fizz::client::CachedPsk> cachedPsk,
      const std::shared_ptr<ClientTransportParametersExtension>&
          transportParams,
      HandshakeCallback* callback);

  /**
   * Takes input bytes from the network and processes then in the handshake.
   * This can change the state of the transport which may result in ciphers
   * being initialized, bytes written out, or the write phase changing.
   */
  virtual void doHandshake(
      std::unique_ptr<folly::IOBuf> data,
      EncryptionLevel encryptionLevel);

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
   * An edge triggered API to get the zeroRttWriteCipher. Once you receive the
   * zero rtt write cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getZeroRttWriteCipher();

  /**
   * An edge triggered API to get the handshakeReadCipher. Once you
   * receive the handshake read cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getHandshakeReadCipher();

  /**
   * An edge triggered API to get the handshakeWriteCipher. Once you
   * receive the handshake write cipher subsequent calls will return null.
   */
  std::unique_ptr<Aead> getHandshakeWriteCipher();

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
   * An edge triggered API to get the zero rtt write header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getZeroRttWriteHeaderCipher();

  /**
   * Notify the crypto layer that we received one rtt protected data.
   * This allows us to know that the peer has implicitly acked the 1-rtt keys.
   */
  void onRecvOneRttProtectedData();

  Phase getPhase() const;

  /**
   * Was the TLS connection resumed or not.
   */
  bool isTLSResumed() const;

  /**
   * Edge triggered api to obtain whether or not zero rtt data was rejected.
   * If zero rtt was never attempted, then this will return folly::none. Once
   * the result is obtained, the result is cleared out.
   */
  folly::Optional<bool> getZeroRttRejected();

  /**
   * Returns the application protocol that was negotiated by the handshake.
   */
  const folly::Optional<std::string>& getApplicationProtocol() const override;

  /**
   * Returns the negotiated transport parameters chosen by the server
   */
  virtual folly::Optional<ServerTransportParameters> getServerTransportParams();

  virtual ~ClientHandshake() = default;

 protected:
  // Represents the packet type that should be used to write the data currently
  // in the stream.
  Phase phase_{Phase::Initial};

  std::unique_ptr<Aead> handshakeWriteCipher_;
  std::unique_ptr<Aead> handshakeReadCipher_;
  std::unique_ptr<Aead> oneRttReadCipher_;
  std::unique_ptr<Aead> oneRttWriteCipher_;
  std::unique_ptr<Aead> zeroRttWriteCipher_;

  std::unique_ptr<PacketNumberCipher> oneRttReadHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> handshakeReadHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> handshakeWriteHeaderCipher_;

  std::unique_ptr<PacketNumberCipher> zeroRttWriteHeaderCipher_;

  folly::Optional<bool> zeroRttRejected_;
  HandshakeCallback* callback_{nullptr};
  QuicCryptoState& cryptoState_;

 private:
  void computeOneRttCipher(
      const fizz::client::ReportHandshakeSuccess& handshakeSuccess);

  void computeZeroRttCipher();

  class ActionMoveVisitor;
  void processActions(fizz::client::Actions actions);

  fizz::client::State state_;
  fizz::client::ClientStateMachine machine_;

  // Whether or not to wait for more data.
  bool waitForData_{false};

  folly::IOBufQueue initialReadBuf_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue handshakeReadBuf_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue appDataReadBuf_{folly::IOBufQueue::cacheChainLength()};

  folly::exception_wrapper error_;

  std::shared_ptr<CryptoFactory> cryptoFactory_;
  std::shared_ptr<ClientTransportParametersExtension> transportParams_;
  bool earlyDataAttempted_{false};
};
} // namespace quic
