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
  return "flow control event, new offset: " + folly::to<std::string>(offset);
}

std::string
getRxStreamWU(StreamId streamId, PacketNum packetNum, uint64_t maximumData) {
  return "rx stream, streamId: " + folly::to<std::string>(streamId) +
      ", packetNum: " + folly::to<std::string>(packetNum) +
      ", maximumData: " + folly::to<std::string>(maximumData);
}

std::string getRxConnWU(PacketNum packetNum, uint64_t maximumData) {
  return "rx, packetNum: " + folly::to<std::string>(packetNum) +
      ", maximumData: " + folly::to<std::string>(maximumData);
}

std::string getPeerClose(const std::string& peerCloseReason) {
  return "error message: " + peerCloseReason;
}

std::string getFlowControlWindowAvailable(uint64_t windowAvailable) {
  return "on flow control, window available: " +
      folly::to<std::string>(windowAvailable);
}

std::string getClosingStream(const std::string& streamId) {
  return "closing stream, stream id: " + streamId;
}

} // namespace quic
