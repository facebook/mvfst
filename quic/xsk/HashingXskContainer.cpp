/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#if defined(__linux__)

#include <quic/xsk/HashingXskContainer.h>

namespace facebook::xdpsocket {

folly::Expected<folly::Unit, std::runtime_error> HashingXskContainer::init(
    const XskContainerConfig& xskContainerConfig) {
  initializeQueueParams(xskContainerConfig.interfaceName);
  for (uint32_t queueId = startQueue_; queueId < startQueue_ + numQueues_;
       ++queueId) {
    uint32_t numOwners = 1;
    XskSenderConfig xskSenderConfig{
        .numFrames = xskContainerConfig.numFrames,
        .frameSize = xskContainerConfig.frameSize,
        .batchSize = xskContainerConfig.batchSize,
        .ownerId = 0,
        .numOwners = numOwners,
        .localMac = xskContainerConfig.localMac,
        .gatewayMac = xskContainerConfig.gatewayMac,
        .zeroCopyEnabled = true,
        .useNeedWakeup = true,
        .sharedState = std::make_shared<SharedState>(numOwners)};
    auto createResult = createXskSender(queueId, xskSenderConfig);
    if (createResult.hasError()) {
      // TODO: Clean up the already-created XDP sockets if we fail at this
      // point.
      return folly::makeUnexpected(createResult.error());
    } else {
      queueIdToXsk_.emplace(queueId, std::move(createResult.value()));
    }
  }
  return folly::Unit();
}

XskSender* HashingXskContainer::pickXsk(
    const folly::SocketAddress& src,
    const folly::SocketAddress& dst) {
  auto queueId = startQueue_ + (src.hash() + dst.hash()) % numQueues_;
  return queueIdToXsk_.at(queueId).get();
}

} // namespace facebook::xdpsocket

#endif
