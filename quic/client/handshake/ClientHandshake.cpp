/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/handshake/ClientHandshake.h>

#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/fizz/client/handshake/QuicPskCache.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

ClientHandshake::ClientHandshake(QuicClientConnectionState* conn)
    : conn_(conn) {}

void ClientHandshake::connect(
    folly::Optional<std::string> hostname,
    std::shared_ptr<ClientTransportParametersExtension> transportParams) {
  transportParams_ = std::move(transportParams);

  folly::Optional<CachedServerTransportParameters> cachedServerTransportParams =
      connectImpl(std::move(hostname));

  throwOnError();

  if (conn_->zeroRttWriteCipher) {
    if (conn_->qLogger) {
      conn_->qLogger->addTransportStateUpdate(kZeroRttAttempted);
    }

    // If zero rtt write cipher is derived, it means the cached psk was valid
    DCHECK(cachedServerTransportParams);
    cacheServerInitialParams(
        *conn_,
        cachedServerTransportParams->initialMaxData,
        cachedServerTransportParams->initialMaxStreamDataBidiLocal,
        cachedServerTransportParams->initialMaxStreamDataBidiRemote,
        cachedServerTransportParams->initialMaxStreamDataUni,
        cachedServerTransportParams->initialMaxStreamsBidi,
        cachedServerTransportParams->initialMaxStreamsUni,
        cachedServerTransportParams->knobFrameSupport);
    updateTransportParamsFromCachedEarlyParams(
        *conn_, *cachedServerTransportParams);
  }
}

void ClientHandshake::doHandshake(
    std::unique_ptr<folly::IOBuf> data,
    EncryptionLevel encryptionLevel) {
  if (!data) {
    return;
  }
  // TODO: deal with clear text alert messages. It's possible that a MITM who
  // mucks with the finished messages could cause the decryption to be invalid
  // on the server, which would result in a cleartext close or a cleartext
  // alert. We currently switch to 1-rtt ciphers immediately for reads and
  // throw away the cleartext cipher for reads, this would result in us
  // dropping the alert and timing out instead.
  if (phase_ == Phase::Initial) {
    // This could be an HRR or a cleartext alert.
    handshakeInitiated();
  }

  // First add it to the right read buffer.
  switch (encryptionLevel) {
    case EncryptionLevel::Initial:
      initialReadBuf_.append(std::move(data));
      break;
    case EncryptionLevel::Handshake:
      handshakeReadBuf_.append(std::move(data));
      break;
    case EncryptionLevel::EarlyData:
    case EncryptionLevel::AppData:
      appDataReadBuf_.append(std::move(data));
      break;
    default:
      LOG(FATAL) << "Unhandled EncryptionLevel";
  }
  // Get the current buffer type the transport is accepting.
  waitForData_ = false;
  while (!waitForData_) {
    switch (getReadRecordLayerEncryptionLevel()) {
      case EncryptionLevel::Initial:
        processSocketData(initialReadBuf_);
        break;
      case EncryptionLevel::Handshake:
        processSocketData(handshakeReadBuf_);
        break;
      case EncryptionLevel::EarlyData:
      case EncryptionLevel::AppData:
        processSocketData(appDataReadBuf_);
        break;
      default:
        LOG(FATAL) << "Unhandled EncryptionLevel";
    }
    throwOnError();
  }
}

void ClientHandshake::handshakeConfirmed() {
  phase_ = Phase::Established;
}

ClientHandshake::Phase ClientHandshake::getPhase() const {
  return phase_;
}

const folly::Optional<ServerTransportParameters>&
ClientHandshake::getServerTransportParams() {
  return transportParams_->getServerTransportParams();
}

folly::Optional<bool> ClientHandshake::getZeroRttRejected() {
  return zeroRttRejected_;
}

void ClientHandshake::computeCiphers(CipherKind kind, folly::ByteRange secret) {
  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> packetNumberCipher;
  std::tie(aead, packetNumberCipher) = buildCiphers(kind, secret);
  switch (kind) {
    case CipherKind::HandshakeWrite:
      conn_->handshakeWriteCipher = std::move(aead);
      conn_->handshakeWriteHeaderCipher = std::move(packetNumberCipher);
      break;
    case CipherKind::HandshakeRead:
      conn_->readCodec->setHandshakeReadCipher(std::move(aead));
      conn_->readCodec->setHandshakeHeaderCipher(std::move(packetNumberCipher));
      break;
    case CipherKind::OneRttWrite:
      conn_->oneRttWriteCipher = std::move(aead);
      conn_->oneRttWriteHeaderCipher = std::move(packetNumberCipher);
      break;
    case CipherKind::OneRttRead:
      conn_->readCodec->setOneRttReadCipher(std::move(aead));
      conn_->readCodec->setOneRttHeaderCipher(std::move(packetNumberCipher));
      break;
    case CipherKind::ZeroRttWrite:
      getClientConn()->zeroRttWriteCipher = std::move(aead);
      getClientConn()->zeroRttWriteHeaderCipher = std::move(packetNumberCipher);
      break;
    default:
      // Report error?
      break;
  }
}

void ClientHandshake::raiseError(folly::exception_wrapper error) {
  error_ = std::move(error);
}

void ClientHandshake::throwOnError() {
  if (error_) {
    error_.throw_exception();
  }
}

void ClientHandshake::waitForData() {
  waitForData_ = true;
}

void ClientHandshake::writeDataToStream(
    EncryptionLevel encryptionLevel,
    Buf data) {
  if (encryptionLevel == EncryptionLevel::AppData) {
    // Don't write 1-rtt handshake data on the client.
    return;
  }
  auto cryptoStream = getCryptoStream(*conn_->cryptoState, encryptionLevel);
  writeDataToQuicStream(*cryptoStream, std::move(data));
}

void ClientHandshake::handshakeInitiated() {
  CHECK(phase_ == Phase::Initial);
  phase_ = Phase::Handshake;
}

void ClientHandshake::computeZeroRttCipher() {
  VLOG(10) << "Computing Client zero rtt keys";
  earlyDataAttempted_ = true;
}

void ClientHandshake::computeOneRttCipher(bool earlyDataAccepted) {
  // The 1-rtt handshake should have succeeded if we know that the early
  // write failed. We currently treat the data as lost.
  // TODO: we need to deal with HRR based rejection as well, however we don't
  // have an API right now.
  if (earlyDataAttempted_ && !earlyDataAccepted) {
    if (matchEarlyParameters()) {
      zeroRttRejected_ = true;
    } else {
      // TODO: support app retry of zero rtt data.
      error_ = folly::make_exception_wrapper<QuicInternalException>(
          "Changing parameters when early data attempted not supported",
          LocalErrorCode::EARLY_DATA_REJECTED);
      return;
    }
  } else if (earlyDataAttempted_ && earlyDataAccepted) {
    zeroRttRejected_ = false;
  }
  // After a successful handshake we should send packets with the type of
  // ClientCleartext. We assume that by the time we get the data for the QUIC
  // stream, the server would have also acked all the client initial packets.
  CHECK(phase_ == Phase::Handshake);
  phase_ = Phase::OneRttKeysDerived;
}

QuicClientConnectionState* ClientHandshake::getClientConn() {
  return conn_;
}

const QuicClientConnectionState* ClientHandshake::getClientConn() const {
  return conn_;
}

const std::shared_ptr<ClientTransportParametersExtension>&
ClientHandshake::getClientTransportParameters() const {
  return transportParams_;
}

void ClientHandshake::setZeroRttRejectedForTest(bool rejected) {
  zeroRttRejected_ = rejected;
}

} // namespace quic
