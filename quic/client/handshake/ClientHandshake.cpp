/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/client/handshake/ClientHandshake.h>

#include <fizz/protocol/Protocol.h>
#include <quic/handshake/FizzBridge.h>
#include <quic/handshake/FizzCryptoFactory.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

ClientHandshake::ClientHandshake(QuicCryptoState& cryptoState)
    : cryptoState_(cryptoState) {}

void ClientHandshake::connect(
    std::shared_ptr<const fizz::client::FizzClientContext> context,
    std::shared_ptr<const fizz::CertificateVerifier> verifier,
    folly::Optional<std::string> hostname,
    folly::Optional<fizz::client::CachedPsk> cachedPsk,
    const std::shared_ptr<ClientTransportParametersExtension>& transportParams,
    HandshakeCallback* callback) {
  transportParams_ = transportParams;
  callback_ = callback;
  auto ctx = std::make_shared<fizz::client::FizzClientContext>(*context);
  auto cryptoFactory = std::make_shared<FizzCryptoFactory>();
  ctx->setFactory(cryptoFactory);
  cryptoFactory_ = std::move(cryptoFactory);
  ctx->setSupportedCiphers({fizz::CipherSuite::TLS_AES_128_GCM_SHA256});
  ctx->setCompatibilityMode(false);
  // Since Draft-17, EOED should not be sent
  ctx->setOmitEarlyRecordLayer(true);
  processActions(machine_.processConnect(
      state_,
      std::move(ctx),
      std::move(verifier),
      std::move(hostname),
      std::move(cachedPsk),
      transportParams));
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
    if (error_) {
      error_.throw_exception();
    }
  }
}

std::unique_ptr<Aead> ClientHandshake::getOneRttWriteCipher() {
  if (error_) {
    error_.throw_exception();
  }
  return std::move(oneRttWriteCipher_);
}

std::unique_ptr<Aead> ClientHandshake::getOneRttReadCipher() {
  if (error_) {
    error_.throw_exception();
  }
  return std::move(oneRttReadCipher_);
}

std::unique_ptr<Aead> ClientHandshake::getZeroRttWriteCipher() {
  if (error_) {
    error_.throw_exception();
  }
  return std::move(zeroRttWriteCipher_);
}

std::unique_ptr<Aead> ClientHandshake::getHandshakeReadCipher() {
  if (error_) {
    error_.throw_exception();
  }
  return std::move(handshakeReadCipher_);
}

std::unique_ptr<Aead> ClientHandshake::getHandshakeWriteCipher() {
  if (error_) {
    error_.throw_exception();
  }
  return std::move(handshakeWriteCipher_);
}

std::unique_ptr<PacketNumberCipher>
ClientHandshake::getOneRttReadHeaderCipher() {
  if (error_) {
    error_.throw_exception();
  }
  return std::move(oneRttReadHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ClientHandshake::getOneRttWriteHeaderCipher() {
  if (error_) {
    error_.throw_exception();
  }
  return std::move(oneRttWriteHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ClientHandshake::getHandshakeReadHeaderCipher() {
  if (error_) {
    error_.throw_exception();
  }
  return std::move(handshakeReadHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ClientHandshake::getHandshakeWriteHeaderCipher() {
  if (error_) {
    error_.throw_exception();
  }
  return std::move(handshakeWriteHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ClientHandshake::getZeroRttWriteHeaderCipher() {
  if (error_) {
    error_.throw_exception();
  }
  return std::move(zeroRttWriteHeaderCipher_);
}

/**
 * Notify the crypto layer that we received one rtt protected data.
 * This allows us to know that the peer has implicitly acked the 1-rtt keys.
 */
void ClientHandshake::onRecvOneRttProtectedData() {
  if (phase_ != Phase::Established) {
    phase_ = Phase::Established;
  }
}

ClientHandshake::Phase ClientHandshake::getPhase() const {
  return phase_;
}

folly::Optional<ServerTransportParameters>
ClientHandshake::getServerTransportParams() {
  return transportParams_->getServerTransportParams();
}

bool ClientHandshake::isTLSResumed() const {
  auto pskType = state_.pskType();
  return pskType && *pskType == fizz::PskType::Resumption;
}

folly::Optional<bool> ClientHandshake::getZeroRttRejected() {
  return std::move(zeroRttRejected_);
}

const folly::Optional<std::string>& ClientHandshake::getApplicationProtocol()
    const {
  auto& earlyDataParams = state_.earlyDataParams();
  if (earlyDataParams) {
    return earlyDataParams->alpn;
  } else {
    return state_.alpn();
  }
}

void ClientHandshake::computeCiphers(CipherKind kind, folly::ByteRange secret) {
  auto aead = buildAead(kind, secret);
  auto packetNumberCipher = cryptoFactory_->makePacketNumberCipher(secret);
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

EncryptionLevel ClientHandshake::getReadRecordLayerEncryptionLevel() {
  return getEncryptionLevelFromFizz(
      state_.readRecordLayer()->getEncryptionLevel());
}

void ClientHandshake::processSocketData(folly::IOBufQueue& queue) {
  processActions(machine_.processSocketData(state_, queue));
}

std::unique_ptr<Aead> ClientHandshake::buildAead(
    CipherKind kind,
    folly::ByteRange secret) {
  bool isEarlyTraffic = kind == CipherKind::ZeroRttWrite;
  fizz::CipherSuite cipher =
      isEarlyTraffic ? state_.earlyDataParams()->cipher : *state_.cipher();
  std::unique_ptr<fizz::KeyScheduler> keySchedulerPtr = isEarlyTraffic
      ? state_.context()->getFactory()->makeKeyScheduler(cipher)
      : nullptr;
  fizz::KeyScheduler& keyScheduler =
      isEarlyTraffic ? *keySchedulerPtr : *state_.keyScheduler();

  return FizzAead::wrap(fizz::Protocol::deriveRecordAeadWithLabel(
      *state_.context()->getFactory(),
      keyScheduler,
      cipher,
      secret,
      kQuicKeyLabel,
      kQuicIVLabel));
}

void ClientHandshake::writeDataToStream(
    EncryptionLevel encryptionLevel,
    Buf data) {
  if (encryptionLevel == EncryptionLevel::AppData) {
    // Don't write 1-rtt handshake data on the client.
    return;
  }
  auto cryptoStream = getCryptoStream(cryptoState_, encryptionLevel);
  writeDataToQuicStream(*cryptoStream, std::move(data));
}

void ClientHandshake::computeZeroRttCipher() {
  VLOG(10) << "Computing Client zero rtt keys";
  CHECK(state_.earlyDataParams().hasValue());
  earlyDataAttempted_ = true;
}

void ClientHandshake::computeOneRttCipher(bool earlyDataAccepted) {
  // The 1-rtt handshake should have succeeded if we know that the early
  // write failed. We currently treat the data as lost.
  // TODO: we need to deal with HRR based rejection as well, however we don't
  // have an API right now.
  if (earlyDataAttempted_ && !earlyDataAccepted) {
    if (fizz::client::earlyParametersMatch(state_)) {
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

class ClientHandshake::ActionMoveVisitor : public boost::static_visitor<> {
 public:
  explicit ActionMoveVisitor(ClientHandshake& client) : client_(client) {}

  void operator()(fizz::DeliverAppData&) {
    client_.error_ = folly::make_exception_wrapper<QuicTransportException>(
        "Invalid app data on crypto stream",
        TransportErrorCode::PROTOCOL_VIOLATION);
  }

  void operator()(fizz::WriteToSocket& write) {
    for (auto& content : write.contents) {
      auto encryptionLevel =
          getEncryptionLevelFromFizz(content.encryptionLevel);
      client_.writeDataToStream(encryptionLevel, std::move(content.data));
    }
  }

  void operator()(fizz::client::ReportEarlyHandshakeSuccess&) {
    client_.computeZeroRttCipher();
  }

  void operator()(fizz::client::ReportHandshakeSuccess& handshakeSuccess) {
    client_.computeOneRttCipher(handshakeSuccess.earlyDataAccepted);
  }

  void operator()(fizz::client::ReportEarlyWriteFailed&) {
    LOG(DFATAL) << "QUIC TLS app data write";
  }

  void operator()(fizz::ReportError& err) {
    auto errMsg = err.error.what();
    if (errMsg.empty()) {
      errMsg = "Error during handshake";
    }

    auto fe = err.error.get_exception<fizz::FizzException>();

    if (fe && fe->getAlert()) {
      auto alertNum =
          static_cast<std::underlying_type<TransportErrorCode>::type>(
              fe->getAlert().value());
      alertNum += static_cast<std::underlying_type<TransportErrorCode>::type>(
          TransportErrorCode::CRYPTO_ERROR);
      client_.error_ = folly::make_exception_wrapper<QuicTransportException>(
          errMsg.toStdString(), static_cast<TransportErrorCode>(alertNum));
    } else {
      client_.error_ = folly::make_exception_wrapper<QuicTransportException>(
          errMsg.toStdString(),
          static_cast<TransportErrorCode>(
              fizz::AlertDescription::internal_error));
    }
  }

  void operator()(fizz::WaitForData&) {
    client_.waitForData_ = true;
  }

  void operator()(fizz::client::MutateState& mutator) {
    mutator(client_.state_);
  }

  void operator()(fizz::client::NewCachedPsk& newCachedPsk) {
    if (client_.callback_) {
      client_.callback_->onNewCachedPsk(newCachedPsk);
    }
  }

  void operator()(fizz::EndOfData&) {
    client_.error_ = folly::make_exception_wrapper<QuicTransportException>(
        "unexpected close notify", TransportErrorCode::INTERNAL_ERROR);
  }

  void operator()(fizz::SecretAvailable& secretAvailable) {
    folly::variant_match(
        secretAvailable.secret.type,
        [&](fizz::EarlySecrets earlySecrets) {
          switch (earlySecrets) {
            case fizz::EarlySecrets::ClientEarlyTraffic:
              client_.computeCiphers(
                  CipherKind::ZeroRttWrite,
                  folly::range(secretAvailable.secret.secret));
              break;
            default:
              break;
          }
        },
        [&](fizz::HandshakeSecrets handshakeSecrets) {
          switch (handshakeSecrets) {
            case fizz::HandshakeSecrets::ClientHandshakeTraffic:
              client_.computeCiphers(
                  CipherKind::HandshakeWrite,
                  folly::range(secretAvailable.secret.secret));
              break;
            case fizz::HandshakeSecrets::ServerHandshakeTraffic:
              client_.computeCiphers(
                  CipherKind::HandshakeRead,
                  folly::range(secretAvailable.secret.secret));
              break;
          }
        },
        [&](fizz::AppTrafficSecrets appSecrets) {
          switch (appSecrets) {
            case fizz::AppTrafficSecrets::ClientAppTraffic:
              client_.computeCiphers(
                  CipherKind::OneRttWrite,
                  folly::range(secretAvailable.secret.secret));
              break;
            case fizz::AppTrafficSecrets::ServerAppTraffic:
              client_.computeCiphers(
                  CipherKind::OneRttRead,
                  folly::range(secretAvailable.secret.secret));
              break;
          }
        },
        [&](auto) {});
  }

 private:
  ClientHandshake& client_;
};

void ClientHandshake::processActions(fizz::client::Actions actions) {
  ActionMoveVisitor visitor(*this);
  for (auto& action : actions) {
    boost::apply_visitor(visitor, action);
  }
}

} // namespace quic
