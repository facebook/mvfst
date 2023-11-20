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

} // namespace

namespace quic {

MbedClientHandshake::MbedClientHandshake(QuicClientConnectionState* conn)
    : ClientHandshake(conn) {
  // init ssl_ctx
  mbedtls_ssl_init(&ssl_ctx);
  // init & apply ssl config defaults
  initSslConfigDefaults(&ssl_conf);
  CHECK_EQ(mbedtls_ssl_setup(&ssl_ctx, &ssl_conf), 0);
}

MbedClientHandshake::~MbedClientHandshake() {
  mbedtls_ssl_free(&ssl_ctx);
  mbedtls_ssl_config_free(&ssl_conf);
}

} // namespace quic
