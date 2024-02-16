/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#if defined(__linux__)

#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <quic/xsk/BaseXskContainer.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

namespace facebook::xdpsocket {

folly::Expected<std::unique_ptr<XskSender>, std::runtime_error>
BaseXskContainer::createXskSender(
    int queueId,
    const XskSenderConfig& xskSenderConfig) {
  auto xskSender = std::make_unique<XskSender>(xskSenderConfig);

  auto initResult = xskSender->init();
  if (initResult.hasError()) {
    return folly::makeUnexpected(initResult.error());
  }

  auto bindResult = xskSender->bind(queueId);
  if (bindResult.hasError()) {
    return folly::makeUnexpected(bindResult.error());
  }

  return xskSender;
}

void BaseXskContainer::initializeQueueParams(const std::string& interfaceName) {
  struct ethtool_channels ethChannels = {
      .cmd = ETHTOOL_GCHANNELS,
  };
  struct ifreq ifr = {
      .ifr_ifru =
          {
              .ifru_data = reinterpret_cast<char*>(&ethChannels),
          },
  };
  strncpy(ifr.ifr_name, interfaceName.c_str(), IFNAMSIZ - 1);

  int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
  if (::ioctl(sock, SIOCETHTOOL, &ifr) < 0) {
    LOG(FATAL) << "Failed to get number of ethernet channels";
  }
  ::close(sock);

  // There are num_rx_queues allocated for TX in XDP, and they are
  // numbered starting at num_tx_queues.
  if (ethChannels.combined_count != 0) {
    startQueue_ = ethChannels.combined_count;
    numQueues_ = ethChannels.combined_count;
  } else {
    startQueue_ = ethChannels.tx_count;
    numQueues_ = ethChannels.rx_count;
  }
}

} // namespace facebook::xdpsocket

#endif
