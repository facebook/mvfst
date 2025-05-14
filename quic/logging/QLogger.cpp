/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/logging/QLogger.h>

#include <quic/codec/Types.h>

namespace quic {

std::string getFlowControlEvent(int offset) {
  return fmt::format("flow control event, new offset: {}", offset);
}

std::string
getRxStreamWU(StreamId streamId, PacketNum packetNum, uint64_t maximumData) {
  return fmt::format(
      "rx stream, streamId: {}, packetNum: {}, maximumData: {}",
      streamId,
      packetNum,
      maximumData);
}

std::string getRxConnWU(PacketNum packetNum, uint64_t maximumData) {
  return fmt::format(
      "rx, packetNum: {}, maximumData: {}", packetNum, maximumData);
}

std::string getPeerClose(const std::string& peerCloseReason) {
  return fmt::format("error message: {}", peerCloseReason);
}

std::string getFlowControlWindowAvailable(uint64_t windowAvailable) {
  return fmt::format("on flow control, window available: {}", windowAvailable);
}

std::string getClosingStream(const std::string& streamId) {
  return fmt::format("closing stream, stream id: {}", streamId);
}

} // namespace quic
