/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/client/handshake/ClientHandshake.h>

#include <quic/client/state/ClientStateMachine.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

ClientHandshake::ClientHandshake(QuicClientConnectionState* conn)
    : conn_(conn) {}

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
    phase_ = Phase::Handshake;
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
    }
    throwOnError();
  }
}

std::unique_ptr<Aead> ClientHandshake::getOneRttWriteCipher() {
  throwOnError();
  return std::move(oneRttWriteCipher_);
}

std::unique_ptr<Aead> ClientHandshake::getOneRttReadCipher() {
  throwOnError();
  return std::move(oneRttReadCipher_);
}

std::unique_ptr<Aead> ClientHandshake::getZeroRttWriteCipher() {
  throwOnError();
  return std::move(zeroRttWriteCipher_);
}

std::unique_ptr<Aead> ClientHandshake::getHandshakeReadCipher() {
  throwOnError();
  return std::move(handshakeReadCipher_);
}

std::unique_ptr<Aead> ClientHandshake::getHandshakeWriteCipher() {
  throwOnError();
  return std::move(handshakeWriteCipher_);
}

std::unique_ptr<PacketNumberCipher>
ClientHandshake::getOneRttReadHeaderCipher() {
  throwOnError();
  return std::move(oneRttReadHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ClientHandshake::getOneRttWriteHeaderCipher() {
  throwOnError();
  return std::move(oneRttWriteHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ClientHandshake::getHandshakeReadHeaderCipher() {
  throwOnError();
  return std::move(handshakeReadHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ClientHandshake::getHandshakeWriteHeaderCipher() {
  throwOnError();
  return std::move(handshakeWriteHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ClientHandshake::getZeroRttWriteHeaderCipher() {
  throwOnError();
  return std::move(zeroRttWriteHeaderCipher_);
}

void ClientHandshake::handshakeConfirmed() {
  phase_ = Phase::Established;
}

ClientHandshake::Phase ClientHandshake::getPhase() const {
  return phase_;
}

folly::Optional<ServerTransportParameters>
ClientHandshake::getServerTransportParams() {
  return transportParams_->getServerTransportParams();
}

folly::Optional<bool> ClientHandshake::getZeroRttRejected() {
  return std::move(zeroRttRejected_);
}

void ClientHandshake::computeCiphers(CipherKind kind, folly::ByteRange secret) {
  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> packetNumberCipher;
  std::tie(aead, packetNumberCipher) = buildCiphers(kind, secret);
  switch (kind) {
    case CipherKind::HandshakeWrite:
      handshakeWriteCipher_ = std::move(aead);
      handshakeWriteHeaderCipher_ = std::move(packetNumberCipher);
      break;
    case CipherKind::HandshakeRead:
      handshakeReadCipher_ = std::move(aead);
      handshakeReadHeaderCipher_ = std::move(packetNumberCipher);
      break;
    case CipherKind::OneRttWrite:
      oneRttWriteCipher_ = std::move(aead);
      oneRttWriteHeaderCipher_ = std::move(packetNumberCipher);
      break;
    case CipherKind::OneRttRead:
      oneRttReadCipher_ = std::move(aead);
      oneRttReadHeaderCipher_ = std::move(packetNumberCipher);
      break;
    case CipherKind::ZeroRttWrite:
      zeroRttWriteCipher_ = std::move(aead);
      zeroRttWriteHeaderCipher_ = std::move(packetNumberCipher);
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
  }
  // After a successful handshake we should send packets with the type of
  // ClientCleartext. We assume that by the time we get the data for the QUIC
  // stream, the server would have also acked all the client initial packets.
  phase_ = Phase::OneRttKeysDerived;
}
} // namespace quic
