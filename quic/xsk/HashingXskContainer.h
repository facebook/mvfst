/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#if defined(__linux__)

#include <folly/container/F14Map.h>
#include <quic/xsk/BaseXskContainer.h>
#include <quic/xsk/XskSender.h>
#include <stdexcept>

namespace facebook::xdpsocket {

/*
 * The Linux Kernel can use one of many strategies to decide which packet to
 * send on which queue: skb hashing, transmit packet steering, or a custom
 * function in the NIC driver. The functionality of the HashingXskContainer is
 * modeled after the skb hashing strategy of the Linux Kernel. We use a hash of
 * the 4-tuple to pick which TX queue a particular packet is written to.
 */
class HashingXskContainer : public BaseXskContainer {
 public:
  HashingXskContainer() = default;

  ~HashingXskContainer() override = default;

  folly::Expected<folly::Unit, std::runtime_error> init(
      const XskContainerConfig& xskContainerConfig) override;

  XskSender* pickXsk(
      const folly::SocketAddress& src,
      const folly::SocketAddress& dst) override;

 private:
  folly::F14FastMap<uint32_t, std::unique_ptr<XskSender>> queueIdToXsk_;
};

} // namespace facebook::xdpsocket

#endif
