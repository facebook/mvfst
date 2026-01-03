/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/handshake/ClientHandshake.h>
#include <quic/common/MvfstLogging.h>

#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/logging/QLoggerMacros.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

ClientHandshake::ClientHandshake(QuicClientConnectionState* conn)
    : conn_(conn) {}

quic::Expected<void, QuicError> ClientHandshake::connect(
    Optional<std::string> hostname,
    std::shared_ptr<ClientTransportParametersExtension> transportParams) {
  transportParams_ = std::move(transportParams);

  auto cachedServerTransportParamsResult = connectImpl(std::move(hostname));
  if (!cachedServerTransportParamsResult.has_value()) {
    return quic::make_unexpected(cachedServerTransportParamsResult.error());
  }

  Optional<CachedServerTransportParameters> cachedServerTransportParams =
      std::move(cachedServerTransportParamsResult.value());

  if (!error_.has_value()) {
    return error_;
  }

  if (conn_->zeroRttWriteCipher) {
    QLOG(*conn_, addTransportStateUpdate, kZeroRttAttempted);

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
        cachedServerTransportParams->knobFrameSupport,
        cachedServerTransportParams->ackReceiveTimestampsEnabled,
        cachedServerTransportParams->maxReceiveTimestampsPerAck,
        cachedServerTransportParams->receiveTimestampsExponent,
        cachedServerTransportParams->reliableStreamResetSupport,
        cachedServerTransportParams->extendedAckFeatures);
    auto result = updateTransportParamsFromCachedEarlyParams(
        *conn_, *cachedServerTransportParams);
    if (!result.has_value()) {
      // Why are we not returning here?
      error_ = quic::make_unexpected(std::move(result.error()));
    }
  }
  return {};
}

quic::Expected<void, QuicError> ClientHandshake::doHandshake(
    quic::BufPtr data,
    EncryptionLevel encryptionLevel) {
  if (!data) {
    return {};
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
      MVLOG_FATAL << "Unhandled EncryptionLevel";
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
        MVLOG_FATAL << "Unhandled EncryptionLevel";
    }
    if (!error_.has_value()) {
      return std::move(error_);
    }
  }
  return {};
}

void ClientHandshake::handshakeConfirmed() {
  phase_ = Phase::Established;
}

ClientHandshake::Phase ClientHandshake::getPhase() const {
  return phase_;
}

const Optional<ServerTransportParameters>&
ClientHandshake::getServerTransportParams() {
  return transportParams_->getServerTransportParams();
}

Optional<bool> ClientHandshake::getZeroRttRejected() {
  return zeroRttRejected_;
}

Optional<bool> ClientHandshake::getCanResendZeroRtt() const {
  return canResendZeroRtt_;
}

size_t ClientHandshake::getInitialReadBufferSize() const {
  return initialReadBuf_.chainLength();
}

size_t ClientHandshake::getHandshakeReadBufferSize() const {
  return handshakeReadBuf_.chainLength();
}

size_t ClientHandshake::getAppDataReadBufferSize() const {
  return appDataReadBuf_.chainLength();
}

bool ClientHandshake::waitingForData() const {
  return waitForData_;
}

void ClientHandshake::computeCiphers(CipherKind kind, ByteRange secret) {
  auto aeadResult = buildAead(kind, secret);
  if (!aeadResult.has_value()) {
    error_ = quic::make_unexpected(std::move(aeadResult.error()));
    return;
  }
  auto packetNumberCipherResult = buildHeaderCipher(secret);
  if (!packetNumberCipherResult.has_value()) {
    error_ = quic::make_unexpected(std::move(packetNumberCipherResult.error()));
    return;
  }

  std::unique_ptr<Aead> aead = std::move(aeadResult.value());
  std::unique_ptr<PacketNumberCipher> packetNumberCipher =
      std::move(packetNumberCipherResult.value());

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
      writeTrafficSecret_ = BufHelpers::copyBuffer(secret);
      conn_->oneRttWriteCipher = std::move(aead);
      conn_->oneRttWriteHeaderCipher = std::move(packetNumberCipher);
      break;
    case CipherKind::OneRttRead: {
      readTrafficSecret_ = BufHelpers::copyBuffer(secret);
      conn_->readCodec->setOneRttReadCipher(std::move(aead));
      conn_->readCodec->setOneRttHeaderCipher(std::move(packetNumberCipher));
      auto nextOneRttReadCipher = getNextOneRttReadCipher();
      if (!nextOneRttReadCipher.has_value()) {
        error_ = quic::make_unexpected(std::move(nextOneRttReadCipher.error()));
        return;
      }
      conn_->readCodec->setNextOneRttReadCipher(
          std::move(nextOneRttReadCipher.value()));
      break;
    }
    case CipherKind::ZeroRttWrite:
      getClientConn()->zeroRttWriteCipher = std::move(aead);
      getClientConn()->zeroRttWriteHeaderCipher = std::move(packetNumberCipher);
      break;
    default:
      // Report error?
      break;
  }
}

quic::Expected<std::unique_ptr<Aead>, QuicError>
ClientHandshake::getNextOneRttWriteCipher() {
  if (!error_.has_value()) {
    return quic::make_unexpected(std::move(error_.error()));
  }

  CHECK(writeTrafficSecret_);
  if (trafficSecretSync_ > 1 || trafficSecretSync_ < -1) {
    MVLOG_WARNING << "Client read and write secrets are out of sync";
  }

  auto nextSecretResult = getNextTrafficSecret(writeTrafficSecret_->coalesce());
  if (!nextSecretResult.has_value()) {
    return quic::make_unexpected(std::move(nextSecretResult.error()));
  }
  writeTrafficSecret_ = std::move(nextSecretResult.value());
  trafficSecretSync_--;

  return buildAead(CipherKind::OneRttWrite, writeTrafficSecret_->coalesce());
}

quic::Expected<std::unique_ptr<Aead>, QuicError>
ClientHandshake::getNextOneRttReadCipher() {
  if (!error_.has_value()) {
    return quic::make_unexpected(std::move(error_.error()));
  }

  CHECK(readTrafficSecret_);
  if (trafficSecretSync_ > 1 || trafficSecretSync_ < -1) {
    MVLOG_WARNING << "Client read and write secrets are out of sync";
  }

  auto nextSecretResult = getNextTrafficSecret(readTrafficSecret_->coalesce());
  if (!nextSecretResult.has_value()) {
    return quic::make_unexpected(std::move(nextSecretResult.error()));
  }
  readTrafficSecret_ = std::move(nextSecretResult.value());
  trafficSecretSync_++;

  return buildAead(CipherKind::OneRttRead, readTrafficSecret_->coalesce());
}

void ClientHandshake::waitForData() {
  waitForData_ = true;
}

void ClientHandshake::writeDataToStream(
    EncryptionLevel encryptionLevel,
    BufPtr data) {
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
  MVVLOG(10) << "Computing Client zero rtt keys";
  earlyDataAttempted_ = true;
}

void ClientHandshake::computeOneRttCipher(bool earlyDataAccepted) {
  // The 1-rtt handshake should have succeeded if we know that the early
  // write failed. We currently treat the data as lost.
  // TODO: we need to deal with HRR based rejection as well, however we don't
  // have an API right now.
  if (earlyDataAttempted_ && !earlyDataAccepted) {
    zeroRttRejected_ = true;

    // If the early parameters don't match. The transport needs to update the
    // parameters or terminate the connection to force the client to retry.
    canResendZeroRtt_ = matchEarlyParameters();
  } else if (earlyDataAttempted_ && earlyDataAccepted) {
    zeroRttRejected_ = false;
  }
  // After a successful handshake we should send packets with the type of
  // ClientCleartext. We assume that by the time we get the data for the QUIC
  // stream, the server would have also acked all the client initial packets.
  CHECK(phase_ == Phase::Handshake);
  phase_ = Phase::OneRttKeysDerived;
}

void ClientHandshake::setError(QuicError error) {
  error_ = quic::make_unexpected(std::move(error));
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

void ClientHandshake::setCanResendZeroRttForTest(bool canResendZeroRtt) {
  canResendZeroRtt_ = canResendZeroRtt;
}

} // namespace quic
