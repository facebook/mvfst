/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/handshake/TransportParameters.h>

namespace quic {

struct ClientTransportParametersExtension {
  ClientTransportParametersExtension(
      QuicVersion encodingVersion,
      uint64_t initialMaxData,
      uint64_t initialMaxStreamDataBidiLocal,
      uint64_t initialMaxStreamDataBidiRemote,
      uint64_t initialMaxStreamDataUni,
      uint64_t initialMaxStreamsBidi,
      uint64_t initialMaxStreamsUni,
      std::chrono::milliseconds idleTimeout,
      uint64_t ackDelayExponent,
      uint64_t maxRecvPacketSize,
      uint64_t activeConnectionIdLimit,
      ConnectionId initialSourceCid,
      std::vector<TransportParameter> customTransportParameters =
          std::vector<TransportParameter>())
      : encodingVersion_(encodingVersion),
        initialMaxData_(initialMaxData),
        initialMaxStreamDataBidiLocal_(initialMaxStreamDataBidiLocal),
        initialMaxStreamDataBidiRemote_(initialMaxStreamDataBidiRemote),
        initialMaxStreamDataUni_(initialMaxStreamDataUni),
        initialMaxStreamsBidi_(initialMaxStreamsBidi),
        initialMaxStreamsUni_(initialMaxStreamsUni),
        idleTimeout_(idleTimeout),
        ackDelayExponent_(ackDelayExponent),
        maxRecvPacketSize_(maxRecvPacketSize),
        activeConnectionLimit_(activeConnectionIdLimit),
        initialSourceCid_(initialSourceCid),
        customTransportParameters_(std::move(customTransportParameters)) {}

  folly::Optional<ServerTransportParameters> getServerTransportParams() {
    return std::move(serverTransportParameters_);
  }

  QuicVersion encodingVersion_;
  uint64_t initialMaxData_;
  uint64_t initialMaxStreamDataBidiLocal_;
  uint64_t initialMaxStreamDataBidiRemote_;
  uint64_t initialMaxStreamDataUni_;
  uint64_t initialMaxStreamsBidi_;
  uint64_t initialMaxStreamsUni_;
  std::chrono::milliseconds idleTimeout_;
  uint64_t ackDelayExponent_;
  uint64_t maxRecvPacketSize_;
  uint64_t activeConnectionLimit_;
  ConnectionId initialSourceCid_;
  folly::Optional<ServerTransportParameters> serverTransportParameters_;
  std::vector<TransportParameter> customTransportParameters_;
};
} // namespace quic
