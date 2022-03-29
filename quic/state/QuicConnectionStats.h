/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <chrono>
#include <string>

#include <folly/SocketAddress.h>
#include <quic/QuicConstants.h>
#include <quic/congestion_control/CongestionController.h>

namespace quic {

struct QuicConnectionStats {
  uint8_t workerID{0};
  uint32_t numConnIDs{0};
  folly::SocketAddress localAddress;
  folly::SocketAddress peerAddress;
  std::chrono::duration<float> duration{0};
  uint64_t cwnd_bytes{0};
  CongestionControlType congestionController;
  CongestionControllerStats congestionControllerStats;
  uint32_t ptoCount{0};
  std::chrono::microseconds srtt{0};
  std::chrono::microseconds mrtt{0};
  std::chrono::microseconds rttvar{0};
  uint64_t peerAckDelayExponent{0};
  uint64_t udpSendPacketLen{0};
  uint64_t numStreams{0};
  std::string clientChosenDestConnectionId;
  std::string clientConnectionId;
  std::string serverConnectionId;
  uint64_t totalBytesSent{0};
  uint64_t totalBytesReceived{0};
  uint64_t totalBytesRetransmitted{0};
  uint32_t version{0};
};

} // namespace quic
