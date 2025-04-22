/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/handshake/ClientHandshake.h>

#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

ClientHandshake::ClientHandshake(QuicClientConnectionState* conn)
    : conn_(conn) {}

folly::Expected<folly::Unit, QuicError> ClientHandshake::connect(
    Optional<std::string> hostname,
    std::shared_ptr<ClientTransportParametersExtension> transportParams) {
  transportParams_ = std::move(transportParams);

  Optional<CachedServerTransportParameters> cachedServerTransportParams =
      connectImpl(std::move(hostname));

  if (error_.hasError()) {
    return error_;
  }

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
        cachedServerTransportParams->knobFrameSupport,
        cachedServerTransportParams->ackReceiveTimestampsEnabled,
        cachedServerTransportParams->maxReceiveTimestampsPerAck,
        cachedServerTransportParams->receiveTimestampsExponent,
        cachedServerTransportParams->reliableStreamResetSupport,
        cachedServerTransportParams->extendedAckFeatures);
    auto result = updateTransportParamsFromCachedEarlyParams(
        *conn_, *cachedServerTransportParams);
    if (result.hasError()) {
      // Why are we not returning here?
      error_ = folly::makeUnexpected(std::move(result.error()));
    }
  }
  return folly::unit;
}

folly::Expected<folly::Unit, QuicError> ClientHandshake::doHandshake(
    quic::BufPtr data,
    EncryptionLevel encryptionLevel) {
  if (!data) {
    return folly::unit;
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
    if (error_.hasError()) {
      return std::move(error_);
    }
  }
  return folly::unit;
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

void ClientHandshake::computeCiphers(CipherKind kind, folly::ByteRange secret) {
  std::unique_ptr<Aead> aead = buildAead(kind, secret);
  std::unique_ptr<PacketNumberCipher> packetNumberCipher =
      buildHeaderCipher(secret);
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
      if (nextOneRttReadCipher.hasError()) {
        error_ = folly::makeUnexpected(std::move(nextOneRttReadCipher.error()));
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

folly::Expected<std::unique_ptr<Aead>, QuicError>
ClientHandshake::getNextOneRttWriteCipher() {
  if (error_.hasError()) {
    return folly::makeUnexpected(std::move(error_.error()));
  }

  CHECK(writeTrafficSecret_);
  LOG_IF(WARNING, trafficSecretSync_ > 1 || trafficSecretSync_ < -1)
      << "Client read and write secrets are out of sync";
  writeTrafficSecret_ = getNextTrafficSecret(writeTrafficSecret_->coalesce());
  trafficSecretSync_--;
  auto cipher =
      buildAead(CipherKind::OneRttWrite, writeTrafficSecret_->coalesce());
  return cipher;
}

folly::Expected<std::unique_ptr<Aead>, QuicError>
ClientHandshake::getNextOneRttReadCipher() {
  if (error_.hasError()) {
    return folly::makeUnexpected(std::move(error_.error()));
  }

  CHECK(readTrafficSecret_);
  LOG_IF(WARNING, trafficSecretSync_ > 1 || trafficSecretSync_ < -1)
      << "Client read and write secrets are out of sync";
  readTrafficSecret_ = getNextTrafficSecret(readTrafficSecret_->coalesce());
  trafficSecretSync_++;
  auto cipher =
      buildAead(CipherKind::OneRttRead, readTrafficSecret_->coalesce());
  return cipher;
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
  VLOG(10) << "Computing Client zero rtt keys";
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
  error_ = folly::makeUnexpected(std::move(error));
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
