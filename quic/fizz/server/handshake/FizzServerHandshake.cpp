/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/server/handshake/FizzServerHandshake.h>

#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/server/handshake/AppToken.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>

#include <fizz/protocol/Protocol.h>
#include <fizz/server/State.h>

// This is necessary for the conversion between QuicServerConnectionState and
// QuicConnectionStateBase and can be removed once ServerHandshake accepts
// QuicServerConnectionState.
#include <quic/server/state/ServerStateMachine.h>

namespace fizz::server {
struct ResumptionState;
} // namespace fizz::server

namespace {
class FailingAppTokenValidator : public fizz::server::AppTokenValidator {
  bool validate(const fizz::server::ResumptionState&) const override {
    return false;
  }
};
} // namespace

namespace quic {

FizzServerHandshake::FizzServerHandshake(
    QuicServerConnectionState* conn,
    std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext,
    std::unique_ptr<CryptoFactory> cryptoFactory)
    : ServerHandshake(conn), fizzContext_(std::move(fizzContext)) {
  CryptoFactory* cryptoFactoryPtr = cryptoFactory.release();
  auto* fizzCryptoFactoryPtr =
      dynamic_cast<FizzCryptoFactory*>(cryptoFactoryPtr);
  if (!fizzCryptoFactoryPtr) {
    cryptoFactory_ = std::make_unique<FizzCryptoFactory>();
  } else {
    cryptoFactory_.reset(fizzCryptoFactoryPtr);
  }
  CHECK(cryptoFactory_ && cryptoFactory_->getFizzFactory());
}

void FizzServerHandshake::initializeImpl(
    HandshakeCallback* callback,
    std::unique_ptr<fizz::server::AppTokenValidator> validator) {
  auto context = std::make_shared<fizz::server::FizzServerContext>(
      *fizzContext_->getContext());
  context->setFactory(cryptoFactory_->getFizzFactory());
  context->setSupportedCiphers({{fizz::CipherSuite::TLS_AES_128_GCM_SHA256}});
  context->setVersionFallbackEnabled(false);
  context->setOmitEarlyRecordLayer(true);
  context->setSendNewSessionTicket(false);
  state_.context() = std::move(context);
  callback_ = callback;

  if (validator) {
    state_.appTokenValidator() = std::move(validator);
  } else {
    state_.appTokenValidator() = std::make_unique<FailingAppTokenValidator>();
  }
}

const CryptoFactory& FizzServerHandshake::getCryptoFactory() const {
  return *cryptoFactory_;
}

const fizz::server::FizzServerContext* FizzServerHandshake::getContext() const {
  return state_.context();
}

EncryptionLevel FizzServerHandshake::getReadRecordLayerEncryptionLevel() {
  return getEncryptionLevelFromFizz(
      state_.readRecordLayer()->getEncryptionLevel());
}

void FizzServerHandshake::processSocketData(folly::IOBufQueue& queue) {
  startActions(
      machine_.processSocketData(state_, queue, fizz::Aead::AeadOptions()));
}

std::unique_ptr<Aead> FizzServerHandshake::buildAead(folly::ByteRange secret) {
  return FizzAead::wrap(fizz::Protocol::deriveRecordAeadWithLabel(
      *state_.context()->getFactory(),
      *state_.keyScheduler(),
      *state_.cipher(),
      secret,
      kQuicKeyLabel,
      kQuicIVLabel));
}
std::unique_ptr<PacketNumberCipher> FizzServerHandshake::buildHeaderCipher(
    folly::ByteRange secret) {
  return cryptoFactory_->makePacketNumberCipher(secret);
}

Buf FizzServerHandshake::getNextTrafficSecret(folly::ByteRange secret) const {
  auto deriver =
      state_.context()->getFactory()->makeKeyDeriver(*state_.cipher());
  auto nextSecret = deriver->expandLabel(
      secret, kQuicKULabel, folly::IOBuf::create(0), secret.size());
  return nextSecret;
}

void FizzServerHandshake::processAccept() {
  addProcessingActions(machine_.processAccept(
      state_, executor_, state_.context(), transportParams_));
}

bool FizzServerHandshake::processPendingCryptoEvent() {
  if (pendingEvents_.empty()) {
    return false;
  }

  auto write = std::move(pendingEvents_.front());
  pendingEvents_.pop_front();
  startActions(machine_.processWriteNewSessionTicket(state_, std::move(write)));
  return true;
}

void FizzServerHandshake::writeNewSessionTicketToCrypto(
    const AppToken& appToken) {
  fizz::WriteNewSessionTicket writeNST;
  writeNST.appToken = encodeAppToken(appToken);
  pendingEvents_.push_back(std::move(writeNST));
}

} // namespace quic
