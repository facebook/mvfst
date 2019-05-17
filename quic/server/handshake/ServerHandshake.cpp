/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/handshake/ServerHandshake.h>

#include <fizz/protocol/Protocol.h>
#include <quic/handshake/FizzBridge.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {
using namespace std::chrono_literals;
ServerHandshake::ServerHandshake(QuicCryptoState& cryptoState)
    : cryptoState_(cryptoState), visitor_(*this) {}

void ServerHandshake::accept(
    std::shared_ptr<ServerTransportParametersExtension> transportParams) {
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  transportParams_ = transportParams;
  inHandshakeStack_ = true;
  addProcessingActions(machine_.processAccept(
      state_, executor_, context_, std::move(transportParams)));
}

void ServerHandshake::initialize(
    folly::Executor* executor,
    std::shared_ptr<const fizz::server::FizzServerContext> context,
    HandshakeCallback* callback,
    std::unique_ptr<fizz::server::AppTokenValidator> validator) {
  executor_ = executor;
  auto ctx = std::make_shared<fizz::server::FizzServerContext>(*context);
  ctx->setFactory(std::make_shared<QuicFizzFactory>());
  ctx->setVersionFallbackEnabled(false);
  // Since Draft-17, client won't sent EOED
  ctx->setOmitEarlyRecordLayer(true);
  context_ = std::move(ctx);
  callback_ = callback;

  if (validator) {
    state_.appTokenValidator() = std::move(validator);
  } else {
    state_.appTokenValidator() = std::make_unique<FailingAppTokenValidator>();
  }
}

void ServerHandshake::doHandshake(
    std::unique_ptr<folly::IOBuf> data,
    fizz::EncryptionLevel encryptionLevel) {
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  inHandshakeStack_ = true;
  waitForData_ = false;
  switch (encryptionLevel) {
    case fizz::EncryptionLevel::Plaintext:
      initialReadBuf_.append(std::move(data));
      break;
    case fizz::EncryptionLevel::Handshake:
      handshakeReadBuf_.append(std::move(data));
      break;
    case fizz::EncryptionLevel::EarlyData:
    case fizz::EncryptionLevel::AppTraffic:
      appDataReadBuf_.append(std::move(data));
      break;
  }
  processPendingEvents();
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
}

void ServerHandshake::writeNewSessionTicket(const AppToken& appToken) {
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  inHandshakeStack_ = true;
  fizz::WriteNewSessionTicket writeNST;
  writeNST.appToken = encodeAppToken(appToken);
  pendingEvents_.push_back(std::move(writeNST));
  processPendingEvents();
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
}

std::unique_ptr<Aead> ServerHandshake::getHandshakeWriteCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return FizzAead::wrap(std::move(handshakeWriteCipher_));
}

std::unique_ptr<Aead> ServerHandshake::getHandshakeReadCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return FizzAead::wrap(std::move(handshakeReadCipher_));
}

std::unique_ptr<Aead> ServerHandshake::getOneRttWriteCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return FizzAead::wrap(std::move(oneRttWriteCipher_));
}

std::unique_ptr<Aead> ServerHandshake::getOneRttReadCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return FizzAead::wrap(std::move(oneRttReadCipher_));
}

std::unique_ptr<Aead> ServerHandshake::getZeroRttReadCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return FizzAead::wrap(std::move(zeroRttReadCipher_));
}

std::unique_ptr<PacketNumberCipher>
ServerHandshake::getOneRttReadHeaderCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(oneRttReadHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ServerHandshake::getOneRttWriteHeaderCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(oneRttWriteHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ServerHandshake::getHandshakeReadHeaderCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(handshakeReadHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ServerHandshake::getHandshakeWriteHeaderCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(handshakeWriteHeaderCipher_);
}

std::unique_ptr<PacketNumberCipher>
ServerHandshake::getZeroRttReadHeaderCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(zeroRttReadHeaderCipher_);
}

/**
 * The application will not get any more callbacks from the handshake layer
 * after this method returns.
 */
void ServerHandshake::cancel() {
  callback_ = nullptr;
}

ServerHandshake::Phase ServerHandshake::getPhase() const {
  return phase_;
}

folly::Optional<ClientTransportParameters>
ServerHandshake::getClientTransportParams() {
  return transportParams_->getClientTransportParams();
}

bool ServerHandshake::isHandshakeDone() {
  return handshakeDone_;
}

const fizz::server::State& ServerHandshake::getState() const {
  return state_;
}

const std::shared_ptr<const fizz::server::FizzServerContext>
ServerHandshake::getContext() const {
  return context_;
}

const folly::Optional<std::string>& ServerHandshake::getApplicationProtocol()
    const {
  return state_.alpn();
}

void ServerHandshake::onError(
    std::pair<std::string, TransportErrorCode> error) {
  VLOG(10) << "ServerHandshake error " << error.first;
  error_ = error;
  handshakeEventAvailable_ = true;
}

void ServerHandshake::onWriteData(fizz::WriteToSocket& write) {
  if (!callback_) {
    // We've been canceled, just return. If we're canceled it's possible that
    // cryptoState_ has been deleted, so let's not refer to it.
    return;
  }
  for (auto& content : write.contents) {
    CHECK(content.encryptionLevel != fizz::EncryptionLevel::EarlyData)
        << "Server cannot write early data";
    if (content.contentType != fizz::ContentType::handshake) {
      continue;
    }
    auto cryptoStream = getCryptoStream(cryptoState_, content.encryptionLevel);
    writeDataToQuicStream(*cryptoStream, std::move(content.data));
  }
  handshakeEventAvailable_ = true;
}

void ServerHandshake::onHandshakeDone() {
  handshakeEventAvailable_ = true;
}

void ServerHandshake::addProcessingActions(fizz::server::AsyncActions actions) {
  if (actionGuard_) {
    onError(std::make_pair(
        "Processing action while pending", TransportErrorCode::INTERNAL_ERROR));
    return;
  }
  actionGuard_ = folly::DelayedDestruction::DestructorGuard(this);
  startActions(std::move(actions));
}

void ServerHandshake::startActions(fizz::server::AsyncActions actions) {
  folly::variant_match(
      actions,
      [this](folly::Future<fizz::server::Actions>& futureActions) {
        std::move(futureActions).then(&ServerHandshake::processActions, this);
      },
      [this](fizz::server::Actions& immediateActions) {
        this->processActions(std::move(immediateActions));
      });
}

void ServerHandshake::processActions(
    fizz::server::ServerStateMachine::CompletedActions actions) {
  // This extra DestructorGuard is needed due to the gap between clearing
  // actionGuard_ and potentially processing another action.
  folly::DelayedDestruction::DestructorGuard dg(this);

  for (auto& action : actions) {
    boost::apply_visitor(visitor_, action);
  }

  actionGuard_.clear();
  if (callback_ && !inHandshakeStack_ && handshakeEventAvailable_) {
    callback_->onCryptoEventAvailable();
  }
  handshakeEventAvailable_ = false;
  processPendingEvents();
}

void ServerHandshake::processPendingEvents() {
  if (inProcessPendingEvents_) {
    return;
  }

  folly::DelayedDestruction::DestructorGuard dg(this);
  inProcessPendingEvents_ = true;
  SCOPE_EXIT {
    inProcessPendingEvents_ = false;
  };

  while (!actionGuard_ && !error_) {
    folly::Optional<fizz::server::ServerStateMachine::ProcessingActions>
        actions;
    actionGuard_ = folly::DelayedDestruction::DestructorGuard(this);
    if (!waitForData_) {
      switch (state_.readRecordLayer()->getEncryptionLevel()) {
        case fizz::EncryptionLevel::Plaintext:
          actions = machine_.processSocketData(state_, initialReadBuf_);
          break;
        case fizz::EncryptionLevel::Handshake:
          actions = machine_.processSocketData(state_, handshakeReadBuf_);
          break;
        case fizz::EncryptionLevel::EarlyData:
        case fizz::EncryptionLevel::AppTraffic:
          // TODO: Get rid of appDataReadBuf_ once we do not need EndOfEarlyData
          // any more.
          actions = machine_.processSocketData(state_, appDataReadBuf_);
          break;
      }
    } else if (!pendingEvents_.empty()) {
      auto event = std::move(pendingEvents_.front());
      pendingEvents_.pop_front();
      folly::variant_match(
          event, [&actions, this](fizz::WriteNewSessionTicket& write) {
            actions =
                machine_.processWriteNewSessionTicket(state_, std::move(write));
          });
    } else {
      actionGuard_.clear();
      return;
    }
    startActions(std::move(*actions));
  }
}

ServerHandshake::ActionMoveVisitor::ActionMoveVisitor(ServerHandshake& server)
    : server_(server) {}

void ServerHandshake::ActionMoveVisitor::operator()(fizz::DeliverAppData&) {
  server_.onError(std::make_pair(
      "Unexpected data on crypto stream",
      TransportErrorCode::PROTOCOL_VIOLATION));
}

void ServerHandshake::ActionMoveVisitor::operator()(
    fizz::WriteToSocket& write) {
  server_.onWriteData(write);
}

void ServerHandshake::ActionMoveVisitor::operator()(
    fizz::server::ReportEarlyHandshakeSuccess&) {
  server_.phase_ = Phase::KeysDerived;
}

void ServerHandshake::ActionMoveVisitor::operator()(
    fizz::server::ReportHandshakeSuccess&) {
  server_.handshakeDone_ = true;
  auto originalPhase = server_.phase_;
  // Fizz only reports handshake success when the server receives the full
  // client finished. At this point we can write any post handshake data and
  // crypto data with the 1-rtt keys.
  server_.phase_ = Phase::Established;
  if (originalPhase != Phase::Handshake) {
    // We already derived the zero rtt keys as well as the one rtt write
    // keys.
    server_.onHandshakeDone();
  }
}

void ServerHandshake::ActionMoveVisitor::operator()(fizz::ReportError& err) {
  auto errMsg = err.error.what();
  if (errMsg.empty()) {
    errMsg = "Error during handshake";
  }

  auto fe = err.error.get_exception<fizz::FizzException>();

  if (fe && fe->getAlert()) {
    auto alertNum = static_cast<std::underlying_type<TransportErrorCode>::type>(
        fe->getAlert().value());
    alertNum += static_cast<std::underlying_type<TransportErrorCode>::type>(
        TransportErrorCode::CRYPTO_ERROR);
    server_.onError(std::make_pair(
        errMsg.toStdString(), static_cast<TransportErrorCode>(alertNum)));
  } else {
    server_.onError(std::make_pair(
        errMsg.toStdString(),
        static_cast<TransportErrorCode>(
            fizz::AlertDescription::internal_error)));
  }
}

void ServerHandshake::ActionMoveVisitor::operator()(fizz::WaitForData&) {
  server_.waitForData_ = true;
}

void ServerHandshake::ActionMoveVisitor::operator()(
    fizz::server::MutateState& mutator) {
  mutator(server_.state_);
}

void ServerHandshake::ActionMoveVisitor::operator()(
    fizz::server::AttemptVersionFallback&) {
  CHECK(false) << "Fallback Unexpected";
}

void ServerHandshake::ActionMoveVisitor::operator()(fizz::EndOfData&) {
  server_.onError(std::make_pair(
      "Unexpected close notify received", TransportErrorCode::INTERNAL_ERROR));
}

void ServerHandshake::ActionMoveVisitor::operator()(
    fizz::SecretAvailable& secretAvailable) {
  auto aead = fizz::Protocol::deriveRecordAeadWithLabel(
      *server_.state_.context()->getFactory(),
      *server_.state_.keyScheduler(),
      *server_.state_.cipher(),
      folly::range(secretAvailable.secret.secret),
      kQuicKeyLabel,
      kQuicIVLabel);
  QuicFizzFactory factory;
  auto headerCipher = makePacketNumberCipher(
      &factory,
      folly::range(secretAvailable.secret.secret),
      *server_.state_.cipher());
  folly::variant_match(
      secretAvailable.secret.type,
      [&](fizz::EarlySecrets earlySecrets) {
        switch (earlySecrets) {
          case fizz::EarlySecrets::ClientEarlyTraffic:
            server_.zeroRttReadCipher_ = std::move(aead);
            server_.zeroRttReadHeaderCipher_ = std::move(headerCipher);
            break;
          default:
            break;
        }
      },
      [&](fizz::HandshakeSecrets handshakeSecrets) {
        switch (handshakeSecrets) {
          case fizz::HandshakeSecrets::ClientHandshakeTraffic:
            server_.handshakeReadCipher_ = std::move(aead);
            server_.handshakeReadHeaderCipher_ = std::move(headerCipher);
            break;
          case fizz::HandshakeSecrets::ServerHandshakeTraffic:
            server_.handshakeWriteCipher_ = std::move(aead);
            server_.handshakeWriteHeaderCipher_ = std::move(headerCipher);
            break;
        }
      },
      [&](fizz::AppTrafficSecrets appSecrets) {
        switch (appSecrets) {
          case fizz::AppTrafficSecrets::ClientAppTraffic:
            server_.oneRttReadCipher_ = std::move(aead);
            server_.oneRttReadHeaderCipher_ = std::move(headerCipher);
            break;
          case fizz::AppTrafficSecrets::ServerAppTraffic:
            server_.oneRttWriteCipher_ = std::move(aead);
            server_.oneRttWriteHeaderCipher_ = std::move(headerCipher);
            break;
        }
      },
      [&](auto) {});
  server_.handshakeEventAvailable_ = true;
}
} // namespace quic
