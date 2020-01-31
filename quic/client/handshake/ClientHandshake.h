/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/client/ClientProtocol.h>

#include <folly/ExceptionWrapper.h>
#include <folly/io/IOBufQueue.h>
#include <folly/io/async/DelayedDestruction.h>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/handshake/Aead.h>
#include <quic/handshake/HandshakeLayer.h>

namespace quic {

class CryptoFactory;
struct QuicClientConnectionState;

class ClientHandshake : public Handshake {
 public:
  class HandshakeCallback {
   public:
    virtual ~HandshakeCallback() = default;

    virtual void onNewCachedPsk(fizz::client::NewCachedPsk&) noexcept = 0;
  };

  enum class Phase { Initial, Handshake, OneRttKeysDerived, Established };

  explicit ClientHandshake(QuicClientConnectionState* conn);

  /**
   * Initiate the handshake with the supplied parameters.
   */
  virtual void connect(
      folly::Optional<std::string> hostname,
      folly::Optional<fizz::client::CachedPsk> cachedPsk,
      std::shared_ptr<ClientTransportParametersExtension> transportParams,
      HandshakeCallback* callback) = 0;

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
   * An edge triggered API to get the one rtt write header cpher. Once you
   * receive the header cipher subsequent calls will return null.
   */
  std::unique_ptr<PacketNumberCipher> getOneRttWriteHeaderCipher();

  /**
   * Returns a reference to the CryptoFactory used internaly.
   */
  virtual const CryptoFactory& getCryptoFactory() const = 0;

  /**
   * Notify the crypto layer that we received one rtt protected data.
   * This allows us to know that the peer has implicitly acked the 1-rtt keys.
   */
  void onRecvOneRttProtectedData();

  Phase getPhase() const;

  /**
   * Was the TLS connection resumed or not.
   */
  virtual bool isTLSResumed() const = 0;

  /**
   * Edge triggered api to obtain whether or not zero rtt data was rejected.
   * If zero rtt was never attempted, then this will return folly::none. Once
   * the result is obtained, the result is cleared out.
   */
  folly::Optional<bool> getZeroRttRejected();

  /**
   * Returns the negotiated transport parameters chosen by the server
   */
  virtual folly::Optional<ServerTransportParameters> getServerTransportParams();

  virtual ~ClientHandshake() = default;

 protected:
  // Represents the packet type that should be used to write the data currently
  // in the stream.
  Phase phase_{Phase::Initial};

  enum class CipherKind {
    HandshakeWrite,
    HandshakeRead,
    OneRttWrite,
    OneRttRead,
    ZeroRttWrite,
  };

  std::unique_ptr<Aead> oneRttWriteCipher_;

  std::unique_ptr<PacketNumberCipher> oneRttWriteHeaderCipher_;

  void computeCiphers(CipherKind kind, folly::ByteRange secret);

  folly::Optional<bool> zeroRttRejected_;
  HandshakeCallback* callback_{nullptr};
  QuicClientConnectionState* conn_;

  /**
   * Various utilities for concrete implementations to use.
   */
  void raiseError(folly::exception_wrapper error);
  void throwOnError();
  void waitForData();
  void writeDataToStream(EncryptionLevel encryptionLevel, Buf data);
  void computeZeroRttCipher();
  void computeOneRttCipher(bool earlyDataAccepted);

 private:
  virtual EncryptionLevel getReadRecordLayerEncryptionLevel() = 0;
  virtual void processSocketData(folly::IOBufQueue& queue) = 0;
  virtual bool matchEarlyParameters() = 0;
  virtual std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
  buildCiphers(CipherKind kind, folly::ByteRange secret) = 0;

  // Whether or not to wait for more data.
  bool waitForData_{false};

  folly::IOBufQueue initialReadBuf_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue handshakeReadBuf_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue appDataReadBuf_{folly::IOBufQueue::cacheChainLength()};

  folly::exception_wrapper error_;

  bool earlyDataAttempted_{false};

 protected:
  std::shared_ptr<ClientTransportParametersExtension> transportParams_;
};

} // namespace quic
