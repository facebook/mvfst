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

/*
 * This class is responsible for the creation and management of XDP
 * sockets. It sets up an XDP socket for each XDP TX queue and decides
 * which packet gets written to which queue. The Linux Kernel can use
 * one of many strategies to decide which packet to send on which queue:
 * skb hashing, transmit packet steering, or a custom function in the NIC
 * driver. The functionality of the XskContainer is modeled after the skb
 * hashing strategy of the Linux Kernel. We use a hash of the 4-tuple to
 * pick which TX queue a particular packet is written to.
 */
class XskContainer {
 public:
  XskContainer() = default;

  folly::Expected<folly::Unit, std::runtime_error> init(
      const std::string& interfaceName,
      const folly::MacAddress& localMac,
      const folly::MacAddress& gatewayMac,
      uint32_t numFrames,
      uint32_t frameSize,
      uint32_t batchSize);

  XskSender* pickXsk(
      const folly::SocketAddress& src,
      const folly::SocketAddress& dst);

 private:
  folly::Expected<folly::Unit, std::runtime_error> createXskSender(
      int queueId,
      const XskSenderConfig& xskSenderConfig);

  void initializeQueueParams();

  std::string interfaceName_;

  folly::F14FastMap<uint32_t, std::unique_ptr<XskSender>> queueIdToXsk_;
  int startQueue_;
  int numQueues_;
};

} // namespace facebook::xdpsocket

#endif
