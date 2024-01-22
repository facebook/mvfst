/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#if defined(__linux__)

#include <folly/Expected.h>
#include <folly/IPAddress.h>
#include <folly/MacAddress.h>
#include <folly/SocketAddress.h>
#include <folly/container/F14Set.h>
#include <folly/io/IOBuf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <quic/xsk/xsk_lib.h>
#include <queue>
#include <stdexcept>

namespace facebook::xdpsocket {

enum class SendResult : uint8_t {
  SUCCESS = 0,
  NO_FREE_DESCRIPTORS = 1,
};

enum class FlushResult : uint8_t {
  SUCCESS = 0,
  FAILED_SENDTO = 1,
};

struct XskBuffer {
  void* buffer; // points to the beginning of the payload, after the headers
  uint32_t frameIndex;
  uint16_t payloadLength; // to be set by the caller
};

class XskSender {
 public:
  XskSender(uint32_t numFrames, uint32_t frameSize, uint32_t batchSize)
      : numFrames_(numFrames), frameSize_(frameSize), batchSize_(batchSize) {
    for (uint32_t i = 0; i < numFrames_; i++) {
      freeUmemIndices_.push(i);
    }
  }

  ~XskSender();

  folly::Optional<XskBuffer> getXskBuffer(bool isIpV6);

  void writeXskBuffer(
      const XskBuffer& xskBuffer,
      const folly::SocketAddress& peer,
      const folly::SocketAddress& src);

  // Return a buffer to the free list without writing it out to
  // the network
  void returnBuffer(const XskBuffer& xskBuffer);

  SendResult writeUdpPacket(
      const folly::SocketAddress& peer,
      const folly::SocketAddress& src,
      const void* data,
      uint16_t len);

  SendResult writeUdpPacket(
      const folly::SocketAddress& peer,
      const folly::SocketAddress& src,
      std::unique_ptr<folly::IOBuf>& data,
      uint16_t len);

  folly::Expected<folly::Unit, std::runtime_error> init(
      const folly::MacAddress& localMac,
      const folly::MacAddress& gatewayMac);

  folly::Expected<folly::Unit, std::runtime_error> bind(int queueId);

  FlushResult flush();

 private:
  void initAddresses(
      const folly::MacAddress& localMac,
      const folly::MacAddress& gatewayMac);

  void writeUdpPacketScaffoldingToBuffer(
      char* buffer,
      const folly::SocketAddress& peer,
      const folly::SocketAddress& src,
      uint16_t payloadLength);

  void writeUdpPacketToBuffer(
      char* buffer,
      const folly::SocketAddress& peer,
      const folly::SocketAddress& src,
      const void* data,
      uint16_t len);

  folly::Expected<folly::Unit, std::runtime_error> initXdpSocket();

  xdp_desc* getTxDescriptor();

  folly::Optional<uint32_t> getFreeUmemIndex();

  void getFreeUmemFrames();

  std::queue<uint32_t> freeUmemIndices_;

  uint32_t numFrames_;
  uint32_t frameSize_;
  uint32_t batchSize_;

  uint32_t numPacketsSentInBatch_{0};

  // We are the producer for the TX ring
  uint32_t txProducerIndex_{0};

  // We are the consumer for the COMP ring
  uint32_t crConsumerIndex_{0};

  void* umemArea_{nullptr};
  void* txMap_{nullptr};
  void* cxMap_{nullptr};
  int xskFd_{-1};
  xdp_mmap_offsets xskOffsets_;

  ethhdr ethhdr_{};
  iphdr iphdr_{};
  ipv6hdr ipv6hdr_{};

  std::mutex m_;
};

} // namespace facebook::xdpsocket

#endif
