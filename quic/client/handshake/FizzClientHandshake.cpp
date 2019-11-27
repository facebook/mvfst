/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/client/handshake/FizzClientHandshake.h>

#include <folly/Overload.h>
#include <quic/client/handshake/FizzClientQuicHandshakeContext.h>
#include <quic/handshake/FizzBridge.h>

#include <fizz/protocol/Protocol.h>

namespace quic {

FizzClientHandshake::FizzClientHandshake(
    QuicCryptoState& cryptoState,
    std::shared_ptr<FizzClientQuicHandshakeContext> fizzContext)
    : ClientHandshake(cryptoState), fizzContext_(std::move(fizzContext)) {}

void FizzClientHandshake::connect(
    folly::Optional<std::string> hostname,
    folly::Optional<fizz::client::CachedPsk> cachedPsk,
    const std::shared_ptr<ClientTransportParametersExtension>& transportParams,
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
      transportParams));
}

const CryptoFactory& FizzClientHandshake::getCryptoFactory() const {
  return cryptoFactory_;
}

void FizzClientHandshake::processSocketData(folly::IOBufQueue& queue) {
  processActions(machine_.processSocketData(state_, queue));
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

class FizzClientHandshake::ActionMoveVisitor : public boost::static_visitor<> {
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
  FizzClientHandshake& client_;
};

void FizzClientHandshake::processActions(fizz::client::Actions actions) {
  ActionMoveVisitor visitor(*this);
  for (auto& action : actions) {
    boost::apply_visitor(visitor, action);
  }
}

} // namespace quic
