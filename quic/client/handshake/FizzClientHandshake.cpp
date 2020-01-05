/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/client/handshake/FizzClientHandshake.h>

#include <quic/client/handshake/FizzClientExtensions.h>
#include <quic/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/fizz/handshake/FizzBridge.h>

#include <fizz/protocol/Protocol.h>

namespace quic {

FizzClientHandshake::FizzClientHandshake(
    QuicCryptoState& cryptoState,
    std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext)
    : ClientHandshake(cryptoState), fizzContext_(std::move(fizzContext)) {}

void FizzClientHandshake::connect(
    folly::Optional<std::string> hostname,
    folly::Optional<fizz::client::CachedPsk> cachedPsk,
    std::shared_ptr<ClientTransportParametersExtension> transportParams,
    HandshakeCallback* callback) {
  transportParams_ = transportParams;
  callback_ = callback;

  // Setup context for this handshake.
  auto context = std::make_shared<fizz::client::FizzClientContext>(
      *fizzContext_->getContext());
  context->setFactory(cryptoFactory_.getFizzFactory());
  context->setSupportedCiphers({fizz::CipherSuite::TLS_AES_128_GCM_SHA256});
  context->setCompatibilityMode(false);
  // Since Draft-17, EOED should not be sent
  context->setOmitEarlyRecordLayer(true);
  processActions(machine_.processConnect(
      state_,
      std::move(context),
      fizzContext_->getCertificateVerifier(),
      std::move(hostname),
      std::move(cachedPsk),
      std::make_shared<FizzClientExtensions>(std::move(transportParams))));
}

const CryptoFactory& FizzClientHandshake::getCryptoFactory() const {
  return cryptoFactory_;
}

const folly::Optional<std::string>&
FizzClientHandshake::getApplicationProtocol() const {
  auto& earlyDataParams = state_.earlyDataParams();
  if (earlyDataParams) {
    return earlyDataParams->alpn;
  } else {
    return state_.alpn();
  }
}

bool FizzClientHandshake::isTLSResumed() const {
  auto pskType = state_.pskType();
  return pskType && *pskType == fizz::PskType::Resumption;
}

EncryptionLevel FizzClientHandshake::getReadRecordLayerEncryptionLevel() {
  return getEncryptionLevelFromFizz(
      state_.readRecordLayer()->getEncryptionLevel());
}

void FizzClientHandshake::processSocketData(folly::IOBufQueue& queue) {
  processActions(machine_.processSocketData(state_, queue));
}

bool FizzClientHandshake::matchEarlyParameters() {
  return fizz::client::earlyParametersMatch(state_);
}

std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
FizzClientHandshake::buildCiphers(CipherKind kind, folly::ByteRange secret) {
  bool isEarlyTraffic = kind == CipherKind::ZeroRttWrite;
  fizz::CipherSuite cipher =
      isEarlyTraffic ? state_.earlyDataParams()->cipher : *state_.cipher();
  std::unique_ptr<fizz::KeyScheduler> keySchedulerPtr = isEarlyTraffic
      ? state_.context()->getFactory()->makeKeyScheduler(cipher)
      : nullptr;
  fizz::KeyScheduler& keyScheduler =
      isEarlyTraffic ? *keySchedulerPtr : *state_.keyScheduler();

  auto aead = FizzAead::wrap(fizz::Protocol::deriveRecordAeadWithLabel(
      *state_.context()->getFactory(),
      keyScheduler,
      cipher,
      secret,
      kQuicKeyLabel,
      kQuicIVLabel));

  auto packetNumberCipher = cryptoFactory_.makePacketNumberCipher(secret);

  return {std::move(aead), std::move(packetNumberCipher)};
}

class FizzClientHandshake::ActionMoveVisitor {
 public:
  explicit ActionMoveVisitor(FizzClientHandshake& client) : client_(client) {}

  void operator()(fizz::DeliverAppData&) {
    client_.raiseError(folly::make_exception_wrapper<QuicTransportException>(
        "Invalid app data on crypto stream",
        TransportErrorCode::PROTOCOL_VIOLATION));
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
      client_.raiseError(folly::make_exception_wrapper<QuicTransportException>(
          errMsg.toStdString(), static_cast<TransportErrorCode>(alertNum)));
    } else {
      client_.raiseError(folly::make_exception_wrapper<QuicTransportException>(
          errMsg.toStdString(),
          static_cast<TransportErrorCode>(
              fizz::AlertDescription::internal_error)));
    }
  }

  void operator()(fizz::WaitForData&) {
    client_.waitForData();
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
    client_.raiseError(folly::make_exception_wrapper<QuicTransportException>(
        "unexpected close notify", TransportErrorCode::INTERNAL_ERROR));
  }

  void operator()(fizz::SecretAvailable& secretAvailable) {
    switch (secretAvailable.secret.type.type()) {
      case fizz::SecretType::Type::EarlySecrets_E:
        switch (*secretAvailable.secret.type.asEarlySecrets()) {
          case fizz::EarlySecrets::ClientEarlyTraffic:
            client_.computeCiphers(
                CipherKind::ZeroRttWrite,
                folly::range(secretAvailable.secret.secret));
            break;
          default:
            break;
        }
        break;
      case fizz::SecretType::Type::HandshakeSecrets_E:
        switch (*secretAvailable.secret.type.asHandshakeSecrets()) {
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
        break;
      case fizz::SecretType::Type::AppTrafficSecrets_E:
        switch (*secretAvailable.secret.type.asAppTrafficSecrets()) {
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
        break;
      case fizz::SecretType::Type::MasterSecrets_E:
        break;
    }
  }

 private:
  FizzClientHandshake& client_;
};

void FizzClientHandshake::processActions(fizz::client::Actions actions) {
  ActionMoveVisitor visitor(*this);
  for (auto& action : actions) {
    switch (action.type()) {
      case fizz::client::Action::Type::DeliverAppData_E:
        visitor(*action.asDeliverAppData());
        break;
      case fizz::client::Action::Type::WriteToSocket_E:
        visitor(*action.asWriteToSocket());
        break;
      case fizz::client::Action::Type::ReportHandshakeSuccess_E:
        visitor(*action.asReportHandshakeSuccess());
        break;
      case fizz::client::Action::Type::ReportEarlyHandshakeSuccess_E:
        visitor(*action.asReportEarlyHandshakeSuccess());
        break;
      case fizz::client::Action::Type::ReportEarlyWriteFailed_E:
        visitor(*action.asReportEarlyWriteFailed());
        break;
      case fizz::client::Action::Type::ReportError_E:
        visitor(*action.asReportError());
        break;
      case fizz::client::Action::Type::EndOfData_E:
        visitor(*action.asEndOfData());
        break;
      case fizz::client::Action::Type::MutateState_E:
        visitor(*action.asMutateState());
        break;
      case fizz::client::Action::Type::WaitForData_E:
        visitor(*action.asWaitForData());
        break;
      case fizz::client::Action::Type::NewCachedPsk_E:
        visitor(*action.asNewCachedPsk());
        break;
      case fizz::client::Action::Type::SecretAvailable_E:
        visitor(*action.asSecretAvailable());
        break;
    }
  }
}

} // namespace quic
