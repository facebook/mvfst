/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#if defined(__linux__)

#include <quic/xsk/ThreadLocalXskContainer.h>

namespace facebook::xdpsocket {

folly::Expected<folly::Unit, std::runtime_error> ThreadLocalXskContainer::init(
    const XskContainerConfig& xskContainerConfig) {
  initializeQueueParams(xskContainerConfig.interfaceName);

  double quotient =
      static_cast<double>(xskContainerConfig.numSockets) / numQueues_;
  uint32_t groupSize = ceil(quotient);
  if (xskContainerConfig.numSockets % numQueues_ != 0) {
    groupSize++;
  }

  uint32_t socketId = 0;
  int qid = startQueue_;
  while (socketId < xskContainerConfig.numSockets) {
    XskSenderConfig xskSenderConfig{
        .numFrames = xskContainerConfig.numFrames,
        .frameSize = xskContainerConfig.frameSize,
        .batchSize = xskContainerConfig.batchSize,
        .ownerId = 0,
        .numOwners = groupSize,
        .localMac = xskContainerConfig.localMac,
        .gatewayMac = xskContainerConfig.gatewayMac,
        .zeroCopyEnabled = true,
        .useNeedWakeup = true,
        .sharedState = std::make_shared<SharedState>(groupSize),
        .xskPerThread = true};

    for (uint32_t i = 0;
         i < groupSize && (socketId + i) < xskContainerConfig.numSockets;
         i++) {
      xskSenderConfig.ownerId = i;
      auto createResultShared = createXskSender(qid, xskSenderConfig);
      if (createResultShared.hasError()) {
        LOG(FATAL) << "Failed to create XskContainer";
      }

      xskSenders_.emplace_back(std::move(*createResultShared));
    }

    socketId += groupSize;
    qid++;
  }
  return folly::Unit();
}

XskSender* ThreadLocalXskContainer::pickXsk(
    const folly::SocketAddress& /* src */,
    const folly::SocketAddress& /* dst */) {
  return xskSender_.get();
}

void ThreadLocalXskContainer::setOwnerForXsk() {
  CHECK_LT(ownerIdToAssign_, xskSenders_.size())
      << "Trying to assign more owners than AF_XDP sockets available";
  xskSender_.reset(
      xskSenders_.at(ownerIdToAssign_++).get(),
      [](auto /* xskSender */, folly::TLPDestructionMode) {});
}

} // namespace facebook::xdpsocket

#endif
