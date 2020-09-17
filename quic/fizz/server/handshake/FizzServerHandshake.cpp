/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/fizz/server/handshake/FizzServerHandshake.h>
#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>

#include <fizz/protocol/Protocol.h>

// This is necessary for the conversion between QuicServerConnectionState and
// QuicConnectionStateBase and can be removed once ServerHandshake accepts
// QuicServerConnectionState.
#include <quic/server/state/ServerStateMachine.h>

namespace quic {

FizzServerHandshake::FizzServerHandshake(
    QuicServerConnectionState* conn,
    std::shared_ptr<FizzServerQuicHandshakeContext> fizzContext)
    : ServerHandshake(conn), fizzContext_(std::move(fizzContext)) {}

void FizzServerHandshake::initializeImpl(
    HandshakeCallback* callback,
    std::unique_ptr<fizz::server::AppTokenValidator> validator) {
  auto context = std::make_shared<fizz::server::FizzServerContext>(
      *fizzContext_->getContext());
  context->setFactory(cryptoFactory_.getFizzFactory());
  context->setSupportedCiphers({{fizz::CipherSuite::TLS_AES_128_GCM_SHA256}});
  context->setVersionFallbackEnabled(false);
  // Since Draft-17, client won't sent EOED
  context->setOmitEarlyRecordLayer(true);
  state_.context() = std::move(context);
  callback_ = callback;

  if (validator) {
    state_.appTokenValidator() = std::move(validator);
  } else {
    state_.appTokenValidator() = std::make_unique<FailingAppTokenValidator>();
  }
}

EncryptionLevel FizzServerHandshake::getReadRecordLayerEncryptionLevel() {
  return getEncryptionLevelFromFizz(
      state_.readRecordLayer()->getEncryptionLevel());
}

std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
FizzServerHandshake::buildCiphers(folly::ByteRange secret) {
  auto aead = FizzAead::wrap(fizz::Protocol::deriveRecordAeadWithLabel(
      *state_.context()->getFactory(),
      *state_.keyScheduler(),
      *state_.cipher(),
      secret,
      kQuicKeyLabel,
      kQuicIVLabel));
  auto headerCipher = cryptoFactory_.makePacketNumberCipher(secret);

  return {std::move(aead), std::move(headerCipher)};
}

const CryptoFactory& FizzServerHandshake::getCryptoFactory() const {
  return cryptoFactory_;
}

void FizzServerHandshake::processAccept() {
  addProcessingActions(machine_.processAccept(
      state_, executor_, state_.context(), transportParams_));
}

const fizz::server::FizzServerContext* FizzServerHandshake::getContext() const {
  return state_.context();
}

void FizzServerHandshake::processSocketData(folly::IOBufQueue& queue) {
  startActions(machine_.processSocketData(state_, queue));
}

} // namespace quic
