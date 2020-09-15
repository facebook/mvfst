/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/handshake/ServerHandshake.h>

#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/state/QuicStreamFunctions.h>

#include <fizz/protocol/Protocol.h>

namespace quic {
ServerHandshake::ServerHandshake(QuicConnectionStateBase* conn)
    : conn_(conn), actionGuard_(nullptr), cryptoState_(*conn->cryptoState) {}

void ServerHandshake::accept(
    std::shared_ptr<ServerTransportParametersExtension> transportParams) {
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  transportParams_ = std::move(transportParams);
  inHandshakeStack_ = true;
  processAccept();
}

void ServerHandshake::initialize(
    folly::Executor* executor,
    HandshakeCallback* callback,
    std::unique_ptr<fizz::server::AppTokenValidator> validator) {
  executor_ = executor;
  initializeImpl(callback, std::move(validator));
}

void ServerHandshake::doHandshake(
    std::unique_ptr<folly::IOBuf> data,
    EncryptionLevel encryptionLevel) {
  SCOPE_EXIT {
    inHandshakeStack_ = false;
  };
  inHandshakeStack_ = true;
  waitForData_ = false;
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
  return std::move(handshakeWriteCipher_);
}

std::unique_ptr<Aead> ServerHandshake::getHandshakeReadCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(handshakeReadCipher_);
}

std::unique_ptr<Aead> ServerHandshake::getOneRttWriteCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(oneRttWriteCipher_);
}

std::unique_ptr<Aead> ServerHandshake::getOneRttReadCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(oneRttReadCipher_);
}

std::unique_ptr<Aead> ServerHandshake::getZeroRttReadCipher() {
  if (error_) {
    throw QuicTransportException(error_->first, error_->second);
  }
  return std::move(zeroRttReadCipher_);
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
    auto encryptionLevel = getEncryptionLevelFromFizz(content.encryptionLevel);
    CHECK(encryptionLevel != EncryptionLevel::EarlyData)
        << "Server cannot write early data";
    if (content.contentType != fizz::ContentType::handshake) {
      continue;
    }
    auto cryptoStream = getCryptoStream(cryptoState_, encryptionLevel);
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
  actionGuard_ = folly::DelayedDestruction::DestructorGuard(conn_);
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

void ServerHandshake::processPendingEvents() {
  if (inProcessPendingEvents_) {
    return;
  }

  folly::DelayedDestruction::DestructorGuard dg(conn_);
  inProcessPendingEvents_ = true;
  SCOPE_EXIT {
    inProcessPendingEvents_ = false;
  };

  while (!actionGuard_ && !error_) {
    folly::Optional<fizz::server::ServerStateMachine::ProcessingActions>
        actions;
    actionGuard_ = folly::DelayedDestruction::DestructorGuard(conn_);
    if (!waitForData_) {
      switch (getReadRecordLayerEncryptionLevel()) {
        case EncryptionLevel::Initial:
          actions.emplace(machine_.processSocketData(state_, initialReadBuf_));
          break;
        case EncryptionLevel::Handshake:
          actions.emplace(
              machine_.processSocketData(state_, handshakeReadBuf_));
          break;
        case EncryptionLevel::EarlyData:
        case EncryptionLevel::AppData:
          // TODO: Get rid of appDataReadBuf_ once we do not need EndOfEarlyData
          // any more.
          actions.emplace(machine_.processSocketData(state_, appDataReadBuf_));
          break;
      }
    } else if (!pendingEvents_.empty()) {
      auto write = std::move(pendingEvents_.front());
      pendingEvents_.pop_front();
      actions.emplace(
          machine_.processWriteNewSessionTicket(state_, std::move(write)));
    } else {
      actionGuard_ = folly::DelayedDestruction::DestructorGuard(nullptr);
      return;
    }
    startActions(std::move(*actions));
  }
}

class ServerHandshake::ActionMoveVisitor : public boost::static_visitor<> {
 public:
  explicit ActionMoveVisitor(ServerHandshake& server) : server_(server) {}

  void operator()(fizz::DeliverAppData&) {
    server_.onError(std::make_pair(
        "Unexpected data on crypto stream",
        TransportErrorCode::PROTOCOL_VIOLATION));
  }

  void operator()(fizz::WriteToSocket& write) {
    server_.onWriteData(write);
  }

  void operator()(fizz::server::ReportEarlyHandshakeSuccess&) {
    server_.phase_ = Phase::KeysDerived;
  }

  void operator()(fizz::server::ReportHandshakeSuccess&) {
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
      server_.onError(std::make_pair(
          errMsg.toStdString(), static_cast<TransportErrorCode>(alertNum)));
    } else {
      server_.onError(std::make_pair(
          errMsg.toStdString(),
          static_cast<TransportErrorCode>(
              fizz::AlertDescription::internal_error)));
    }
  }

  void operator()(fizz::WaitForData&) {
    server_.waitForData_ = true;
  }

  void operator()(fizz::server::MutateState& mutator) {
    mutator(server_.state_);
  }

  void operator()(fizz::server::AttemptVersionFallback&) {
    CHECK(false) << "Fallback Unexpected";
  }

  void operator()(fizz::EndOfData&) {
    server_.onError(std::make_pair(
        "Unexpected close notify received",
        TransportErrorCode::INTERNAL_ERROR));
  }

  void operator()(fizz::SecretAvailable& secretAvailable) {
    auto aead = fizz::Protocol::deriveRecordAeadWithLabel(
        *server_.state_.context()->getFactory(),
        *server_.state_.keyScheduler(),
        *server_.state_.cipher(),
        folly::range(secretAvailable.secret.secret),
        kQuicKeyLabel,
        kQuicIVLabel);
    auto headerCipher = server_.getCryptoFactory().makePacketNumberCipher(
        folly::range(secretAvailable.secret.secret));
    switch (secretAvailable.secret.type.type()) {
      case fizz::SecretType::Type::EarlySecrets_E:
        switch (*secretAvailable.secret.type.asEarlySecrets()) {
          case fizz::EarlySecrets::ClientEarlyTraffic:
            server_.zeroRttReadCipher_ = FizzAead::wrap(std::move(aead));
            server_.zeroRttReadHeaderCipher_ = std::move(headerCipher);
            break;
          default:
            break;
        }
        break;
      case fizz::SecretType::Type::HandshakeSecrets_E:
        switch (*secretAvailable.secret.type.asHandshakeSecrets()) {
          case fizz::HandshakeSecrets::ClientHandshakeTraffic:
            server_.handshakeReadCipher_ = FizzAead::wrap(std::move(aead));
            server_.handshakeReadHeaderCipher_ = std::move(headerCipher);
            break;
          case fizz::HandshakeSecrets::ServerHandshakeTraffic:
            server_.handshakeWriteCipher_ = FizzAead::wrap(std::move(aead));
            server_.handshakeWriteHeaderCipher_ = std::move(headerCipher);
            break;
        }
        break;
      case fizz::SecretType::Type::AppTrafficSecrets_E:
        switch (*secretAvailable.secret.type.asAppTrafficSecrets()) {
          case fizz::AppTrafficSecrets::ClientAppTraffic:
            server_.oneRttReadCipher_ = FizzAead::wrap(std::move(aead));
            server_.oneRttReadHeaderCipher_ = std::move(headerCipher);
            break;
          case fizz::AppTrafficSecrets::ServerAppTraffic:
            server_.oneRttWriteCipher_ = FizzAead::wrap(std::move(aead));
            server_.oneRttWriteHeaderCipher_ = std::move(headerCipher);
            break;
        }
        break;
      case fizz::SecretType::Type::MasterSecrets_E:
        break;
    }
    server_.handshakeEventAvailable_ = true;
  }

 private:
  ServerHandshake& server_;
};

void ServerHandshake::processActions(
    fizz::server::ServerStateMachine::CompletedActions actions) {
  // This extra DestructorGuard is needed due to the gap between clearing
  // actionGuard_ and potentially processing another action.
  folly::DelayedDestruction::DestructorGuard dg(conn_);

  ActionMoveVisitor visitor(*this);
  for (auto& action : actions) {
    switch (action.type()) {
      case fizz::server::Action::Type::DeliverAppData_E:
        visitor(*action.asDeliverAppData());
        break;
      case fizz::server::Action::Type::WriteToSocket_E:
        visitor(*action.asWriteToSocket());
        break;
      case fizz::server::Action::Type::ReportHandshakeSuccess_E:
        visitor(*action.asReportHandshakeSuccess());
        break;
      case fizz::server::Action::Type::ReportEarlyHandshakeSuccess_E:
        visitor(*action.asReportEarlyHandshakeSuccess());
        break;
      case fizz::server::Action::Type::ReportError_E:
        visitor(*action.asReportError());
        break;
      case fizz::server::Action::Type::EndOfData_E:
        visitor(*action.asEndOfData());
        break;
      case fizz::server::Action::Type::MutateState_E:
        visitor(*action.asMutateState());
        break;
      case fizz::server::Action::Type::WaitForData_E:
        visitor(*action.asWaitForData());
        break;
      case fizz::server::Action::Type::AttemptVersionFallback_E:
        visitor(*action.asAttemptVersionFallback());
        break;
      case fizz::server::Action::Type::SecretAvailable_E:
        visitor(*action.asSecretAvailable());
        break;
    }
  }

  actionGuard_ = folly::DelayedDestruction::DestructorGuard(nullptr);
  if (callback_ && !inHandshakeStack_ && handshakeEventAvailable_) {
    callback_->onCryptoEventAvailable();
  }
  handshakeEventAvailable_ = false;
  processPendingEvents();
}

} // namespace quic
