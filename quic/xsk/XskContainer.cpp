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
#include <quic/xsk/XskContainer.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace facebook::xdpsocket {

folly::Expected<folly::Unit, std::runtime_error> XskContainer::init(
    const std::string& interfaceName,
    const folly::MacAddress& localMac,
    const folly::MacAddress& gatewayMac,
    uint32_t numFrames,
    uint32_t frameSize,
    uint32_t batchSize) {
  interfaceName_ = interfaceName;
  initializeQueueParams();
  for (int queueId = startQueue_; queueId < startQueue_ + numQueues_;
       ++queueId) {
    auto createResult = createXskSender(
        queueId, localMac, gatewayMac, numFrames, frameSize, batchSize);
    if (createResult.hasError()) {
      // TODO: Clean up the already-created XDP sockets if we fail at this
      // point.
      return folly::makeUnexpected(createResult.error());
    }
  }
  return folly::Unit();
}

XskBuffer XskContainer::getXskBuffer(
    const folly::SocketAddress& src,
    const folly::SocketAddress& dst) {
  auto queueId = pickXsk(src, dst);
  auto maybeXskBuffer =
      queueIdToXsk_.at(queueId)->getXskBuffer(src.getIPAddress().isV6());
  return *maybeXskBuffer;
}

void XskContainer::writeXskBuffer(
    const XskBuffer& xskBuffer,
    const folly::SocketAddress& src,
    const folly::SocketAddress& dst) {
  auto queueId = pickXsk(src, dst);
  queueIdToXsk_.at(queueId)->writeXskBuffer(xskBuffer, dst, src);
}

folly::Expected<folly::Unit, std::runtime_error> XskContainer::createXskSender(
    int queueId,
    const folly::MacAddress& localMac,
    const folly::MacAddress& gatewayMac,
    uint32_t numFrames,
    uint32_t frameSize,
    uint32_t batchSize) {
  auto xskSender = std::make_unique<XskSender>(numFrames, frameSize, batchSize);

  auto initResult = xskSender->init(localMac, gatewayMac);
  if (initResult.hasError()) {
    return folly::makeUnexpected(initResult.error());
  }

  auto bindResult = xskSender->bind(queueId);
  if (bindResult.hasError()) {
    return folly::makeUnexpected(bindResult.error());
  }

  queueIdToXsk_[queueId] = std::move(xskSender);
  return folly::Unit();
}

void XskContainer::returnBuffer(
    const XskBuffer& xskBuffer,
    const folly::SocketAddress& src,
    const folly::SocketAddress& dst) {
  auto queueId = pickXsk(src, dst);
  queueIdToXsk_.at(queueId)->returnBuffer(xskBuffer);
}

int XskContainer::pickXsk(
    const folly::SocketAddress& src,
    const folly::SocketAddress& dst) {
  return startQueue_ + (src.hash() + dst.hash()) % numQueues_;
}

void XskContainer::initializeQueueParams() {
  struct ethtool_channels ethChannels = {
      .cmd = ETHTOOL_GCHANNELS,
  };
  struct ifreq ifr = {
      .ifr_ifru =
          {
              .ifru_data = reinterpret_cast<char*>(&ethChannels),
          },
  };
  strncpy(ifr.ifr_name, interfaceName_.c_str(), IFNAMSIZ - 1);

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
