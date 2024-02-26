/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#if defined(__linux__)

#include <folly/ThreadLocal.h>
#include <folly/container/F14Map.h>
#include <quic/xsk/BaseXskContainer.h>
#include <quic/xsk/XskSender.h>
#include <stdexcept>

namespace facebook::xdpsocket {

class ThreadLocalXskContainer : public BaseXskContainer {
 public:
  ThreadLocalXskContainer() = default;

  ~ThreadLocalXskContainer() override = default;

  folly::Expected<folly::Unit, std::runtime_error> init(
      const XskContainerConfig& xskContainerConfig) override;

  XskSender* pickXsk(
      const folly::SocketAddress& src,
      const folly::SocketAddress& dst) override;

  // The user needs to call this function within each thread that
  // will use an AF_XDP socket, in order to set the thread local
  // XskSender.
  void setOwnerForXsk();

 private:
  std::vector<std::unique_ptr<XskSender>> xskSenders_;
  uint32_t ownerIdToAssign_{0};
  folly::ThreadLocalPtr<XskSender> xskSender_;
};

} // namespace facebook::xdpsocket

#endif
