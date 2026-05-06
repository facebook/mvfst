/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/logging/oops_logger/OopsFields.h>
#include <quic/state/StateData.h>

namespace proto_oops {

// Adds connection-derived OOPS fields that are commonly useful across QUIC
// callsites, such as version, ALPN, and connection ID.
inline void addConnectionSpecificOopsFields(
    OopsFieldsBuilder& builder,
    const quic::QuicConnectionStateBase& conn) {
  if (conn.version.has_value()) {
    builder.setVersion(static_cast<uint32_t>(*conn.version));
  } else if (conn.originalVersion.has_value()) {
    builder.setVersion(static_cast<uint32_t>(*conn.originalVersion));
  }

  if (conn.handshakeLayer) {
    const auto& alpn = conn.handshakeLayer->getApplicationProtocol();
    if (alpn.has_value()) {
      builder.setAlpn(*alpn);
    }
  }

  if (conn.serverConnectionId.has_value()) {
    builder.setConnectionId(conn.serverConnectionId->hex());
  } else if (conn.clientChosenDestConnectionId.has_value()) {
    builder.setConnectionId(conn.clientChosenDestConnectionId->hex());
  } else if (conn.clientConnectionId.has_value()) {
    builder.setConnectionId(conn.clientConnectionId->hex());
  }
}

// Returns a new OopsFieldsBuilder pre-populated with connection-derived
// fields from `conn`.
inline OopsFieldsBuilder makeConnectionSpecificOopsFieldsBuilder(
    const quic::QuicConnectionStateBase& conn) {
  auto builder = OopsFieldsBuilder();
  addConnectionSpecificOopsFields(builder, conn);
  return builder;
}

} // namespace proto_oops
