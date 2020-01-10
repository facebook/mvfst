/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/fizz/handshake/FizzTransportParameters.h>

namespace quic {

struct ClientTransportParametersExtension {
  ClientTransportParametersExtension(
      folly::Optional<QuicVersion> initialVersion,
      uint64_t initialMaxData,
      uint64_t initialMaxStreamDataBidiLocal,
      uint64_t initialMaxStreamDataBidiRemote,
      uint64_t initialMaxStreamDataUni,
      std::chrono::milliseconds idleTimeout,
      uint64_t ackDelayExponent,
      uint64_t maxRecvPacketSize,
      uint64_t activeConnectionIdLimit,
      std::vector<TransportParameter> customTransportParameters =
          std::vector<TransportParameter>())
      : initialVersion_(initialVersion),
        initialMaxData_(initialMaxData),
        initialMaxStreamDataBidiLocal_(initialMaxStreamDataBidiLocal),
        initialMaxStreamDataBidiRemote_(initialMaxStreamDataBidiRemote),
        initialMaxStreamDataUni_(initialMaxStreamDataUni),
        idleTimeout_(idleTimeout),
        ackDelayExponent_(ackDelayExponent),
        maxRecvPacketSize_(maxRecvPacketSize),
        activeConnectionLimit_(activeConnectionIdLimit),
        customTransportParameters_(customTransportParameters) {}

  folly::Optional<ServerTransportParameters> getServerTransportParams() {
    return std::move(serverTransportParameters_);
  }

  folly::Optional<QuicVersion> initialVersion_;
  uint64_t initialMaxData_;
  uint64_t initialMaxStreamDataBidiLocal_;
  uint64_t initialMaxStreamDataBidiRemote_;
  uint64_t initialMaxStreamDataUni_;
  std::chrono::milliseconds idleTimeout_;
  uint64_t ackDelayExponent_;
  uint64_t maxRecvPacketSize_;
  uint64_t activeConnectionLimit_;
  folly::Optional<ServerTransportParameters> serverTransportParameters_;
  std::vector<TransportParameter> customTransportParameters_;
};
} // namespace quic
