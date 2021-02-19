/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <chrono>
#include <string>

using namespace std::chrono_literals;

namespace quic {

struct BbrStats {
  uint8_t state;
};

struct CopaStats {
  double deltaParam;
  bool useRttStanding;
};

struct CubicStats {
  uint8_t state;
};

union CongestionControllerStats {
  struct BbrStats bbrStats;
  struct CopaStats copaStats;
  struct CubicStats cubicStats;
};

struct QuicConnectionStats {
  uint8_t workerID{0};
  uint32_t numConnIDs{0};
  std::string localAddress;
  std::string peerAddress;
  std::chrono::duration<float> duration{0};
  uint64_t cwnd_bytes{0};
  std::string congestionController;
  CongestionControllerStats congestionControllerStats;
  uint32_t ptoCount{0};
  std::chrono::duration<float> srtt{0ms};
  std::chrono::duration<float> rttvar{0ms};
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
