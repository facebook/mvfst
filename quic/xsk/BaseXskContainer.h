/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#if defined(__linux__)

#include <folly/container/F14Map.h>
#include <quic/xsk/XskSender.h>
#include <stdexcept>

namespace facebook::xdpsocket {

struct XskContainerConfig {
  std::string interfaceName;
  folly::MacAddress localMac;
  folly::MacAddress gatewayMac;
  uint32_t numFrames;
  uint32_t frameSize;
  uint32_t batchSize;
  uint32_t numSockets;
};

class BaseXskContainer {
 public:
  BaseXskContainer() = default;

  virtual ~BaseXskContainer() = default;

  virtual folly::Expected<folly::Unit, std::runtime_error> init(
      const XskContainerConfig& xskContainerConfig) = 0;

  virtual XskSender* pickXsk(
      const folly::SocketAddress& src,
      const folly::SocketAddress& dst) = 0;

 protected:
  folly::Expected<std::unique_ptr<XskSender>, std::runtime_error>
  createXskSender(int queueId, const XskSenderConfig& xskSenderConfig);

  void initializeQueueParams(const std::string& interfaceName);

  uint32_t startQueue_;
  uint32_t numQueues_;
};

} // namespace facebook::xdpsocket

#endif
