/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/mbed/MbedClientHandshake.h>

namespace {

static int kSSLPresetQuicCiphersuites[] = {
    MBEDTLS_TLS1_3_AES_128_GCM_SHA256,
    0};

static mbedtls_ecp_group_id kSSLPresentQuicCurves[] = {
    MBEDTLS_ECP_DP_CURVE25519,
    MBEDTLS_ECP_DP_SECP256R1,
    MBEDTLS_ECP_DP_NONE};

/**
 * Initializes and applies preset default values on config.
 * TODO(@damlaj) – needs improvement, as of now we construct and initialize one
 * mbedtls_ssl_config per handshake/connection as opposed to once per
 * process
 */
void initSslConfigDefaults(mbedtls_ssl_config* conf) {
  // init config and apply defaults
  mbedtls_ssl_config_init(conf);
  mbedtls_ssl_config_defaults(
      conf,
      MBEDTLS_SSL_IS_CLIENT,
      MBEDTLS_SSL_TRANSPORT_QUIC,
      MBEDTLS_SSL_PRESET_DEFAULT);

  // set min & max version to tls13
  mbedtls_ssl_conf_min_version(
      conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);
  mbedtls_ssl_conf_max_version(
      conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_4);

  // only supports one cipher suite for now
  mbedtls_ssl_conf_ciphersuites(conf, kSSLPresetQuicCiphersuites);
  mbedtls_ssl_conf_curves(conf, kSSLPresentQuicCurves);

  mbedtls_ssl_conf_tls13_key_exchange(
      conf,
      MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_PSK_DHE_KE |
          MBEDTLS_SSL_TLS13_KEY_EXCHANGE_MODE_ECDHE_ECDSA);

  // TODO(@damlaj) does not verify server certificate
  mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);

  // TODO(@damlaj) early data support likely goes here
}

// convert mbedtls_ssl_crypto_level to quic::EncryptionLevel
quic::EncryptionLevel toQuicEncLevel(mbedtls_ssl_crypto_level level) {
  switch (level) {
    case MBEDTLS_SSL_CRYPTO_LEVEL_INITIAL:
      return quic::EncryptionLevel::Initial;
    case MBEDTLS_SSL_CRYPTO_LEVEL_HANDSHAKE:
      return quic::EncryptionLevel::Handshake;
    case MBEDTLS_SSL_CRYPTO_LEVEL_APPLICATION:
      return quic::EncryptionLevel::AppData;
    case MBEDTLS_SSL_CRYPTO_LEVEL_EARLY_DATA:
      return quic::EncryptionLevel::EarlyData;
    default:
      folly::assume_unreachable();
  };
}

} // namespace

namespace quic {

/**
 * MbedTlsQuicMethodCb is a friend struct of MbedClientHandshake that proxies
 * c-style callbacks to the corresponding private MbedClientHandshake member
 * methods. We likely don't want mbed callbacks to be exposed publicly.
 */
struct MbedTlsQuicMethodCb {
  // cb invoked when secrets are derived by the tls layer for a given enc level
  static int mbedtls_quic_set_encryption_secrets(
      void* param,
      mbedtls_ssl_crypto_level level,
      const uint8_t* read_secret,
      const uint8_t* write_secret,
      size_t len) {
    return reinterpret_cast<MbedClientHandshake*>(param)->setEncryptionSecrets(
        toQuicEncLevel(level), read_secret, write_secret, len);
  }

  // cb invoked when new handshake data is available to send to peer
  static int mbedtls_quic_add_handshake_data(
      void* param,
      mbedtls_ssl_crypto_level level,
      const uint8_t* data,
      size_t len) {
    return reinterpret_cast<MbedClientHandshake*>(param)->addHandshakeData(
        toQuicEncLevel(level), data, len);
  }

  // cb invoked to inform quic to deliver alert to peer
  static int mbedtls_quic_send_alert(
      void* param,
      mbedtls_ssl_crypto_level level,
      uint8_t alert) {
    return reinterpret_cast<MbedClientHandshake*>(param)->sendAlert(
        toQuicEncLevel(level), alert);
  }

  // cb invoked on new TLS session
  static void mbedtls_quic_process_new_session(
      void* param,
      mbedtls_ssl_session* session_ticket) {
    return reinterpret_cast<MbedClientHandshake*>(param)->processNewSession(
        session_ticket);
  }
};

struct mbedtls_quic_method mbedtls_quic_method_cb {
  .set_encryption_secrets =
      MbedTlsQuicMethodCb::mbedtls_quic_set_encryption_secrets,
  .add_handshake_data = MbedTlsQuicMethodCb::mbedtls_quic_add_handshake_data,
  .send_alert = MbedTlsQuicMethodCb::mbedtls_quic_send_alert,
  .process_new_session = MbedTlsQuicMethodCb::mbedtls_quic_process_new_session,
};

MbedClientHandshake::MbedClientHandshake(QuicClientConnectionState* conn)
    : ClientHandshake(conn) {
  // init ssl_ctx
  mbedtls_ssl_init(&ssl_ctx);
  // init & apply ssl config defaults
  initSslConfigDefaults(&ssl_conf);
  CHECK_EQ(mbedtls_ssl_setup(&ssl_ctx, &ssl_conf), 0);

  // install quic callbacks
  mbedtls_ssl_set_hs_quic_method(&ssl_ctx, this, &mbedtls_quic_method_cb);
}

MbedClientHandshake::~MbedClientHandshake() {
  mbedtls_ssl_free(&ssl_ctx);
  mbedtls_ssl_config_free(&ssl_conf);
}

std::pair<std::unique_ptr<Aead>, std::unique_ptr<PacketNumberCipher>>
MbedClientHandshake::buildCiphers(CipherKind kind, folly::ByteRange secret) {
  // TODO(@damlaj) support 0-rtt
  CHECK(kind != CipherKind::ZeroRttWrite);

  // TODO(@damlaj) support other cipher suites
  auto aead = crypto_factory.makeQuicAead(CipherType::AESGCM128, secret);
  auto packetnum_cipher = crypto_factory.makePacketNumberCipher(secret);
  return {std::move(aead), std::move(packetnum_cipher)};
}

// cb invoked when secrets are derived by the tls layer for a given enc level
int MbedClientHandshake::setEncryptionSecrets(
    EncryptionLevel level,
    const uint8_t* readKey,
    const uint8_t* writeKey,
    size_t length) {
  // at least one of the keys should be available
  CHECK(readKey != nullptr || writeKey != nullptr);

  if (readKey != nullptr) {
    folly::ByteRange key_bytes(readKey, length);
    switch (level) {
      case EncryptionLevel::Handshake:
        computeCiphers(CipherKind::HandshakeRead, key_bytes);
        break;
      case EncryptionLevel::AppData:
        computeCiphers(CipherKind::OneRttRead, key_bytes);
        break;
      default:
        /**
         * - Initial read/write keys are obtained via
         *   MbedCryptoFactory::makeInitialAead()
         *
         * - 0-rtt not yet supported
         */
        break;
    }
  }

  if (writeKey != nullptr) {
    folly::ByteRange key_bytes(writeKey, length);
    switch (level) {
      case EncryptionLevel::Handshake:
        computeCiphers(CipherKind::HandshakeWrite, key_bytes);
        break;
      case EncryptionLevel::AppData:
        computeCiphers(CipherKind::OneRttWrite, key_bytes);
        break;
      default:
        /**
         * - Initial read/write keys are obtained via
         *   MbedCryptoFactory::makeInitialAead()
         *
         * - 0-rtt not yet supported
         */
        break;
    }
  }

  return 0;
}

} // namespace quic
