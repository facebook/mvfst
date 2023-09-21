/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>

#include <memory>
#include <vector>

namespace quic {

struct ReceivedPacket {
  ReceivedPacket() = default;
  explicit ReceivedPacket(Buf&& bufIn) : buf(std::move(bufIn)) {}

  // data
  Buf buf;
};

struct NetworkData {
  TimePoint receiveTimePoint;
  std::vector<ReceivedPacket> packets;
  size_t totalData{0};

  NetworkData() = default;
  NetworkData(Buf&& buf, const TimePoint& receiveTime)
      : receiveTimePoint(receiveTime) {
    if (buf) {
      totalData = buf->computeChainDataLength();
      packets.emplace_back(std::move(buf));
    }
  }

  NetworkData(
      std::vector<Buf>&& packetBufs,
      const TimePoint& receiveTimePointIn)
      : receiveTimePoint(receiveTimePointIn),
        packets([&packetBufs]() {
          std::vector<ReceivedPacket> result;
          result.reserve(packetBufs.size());
          for (auto& packetBuf : packetBufs) {
            result.emplace_back(std::move(packetBuf));
          }
          return result;
        }()),
        totalData([this]() {
          size_t result = 0;
          for (const auto& packet : packets) {
            result += packet.buf->computeChainDataLength();
          }
          return result;
        }()) {}

  std::unique_ptr<folly::IOBuf> moveAllData() && {
    std::unique_ptr<folly::IOBuf> buf;
    for (auto& packet : packets) {
      if (buf) {
        buf->prependChain(std::move(packet.buf));
      } else {
        buf = std::move(packet.buf);
      }
    }
    return buf;
  }
};

struct NetworkDataSingle {
  ReceivedPacket packet;
  TimePoint receiveTimePoint;
  size_t totalData{0};

  NetworkDataSingle() = default;

  NetworkDataSingle(
      ReceivedPacket&& packetIn,
      const TimePoint& receiveTimePointIn)
      : packet(std::move(packetIn)), receiveTimePoint(receiveTimePointIn) {
    if (packet.buf) {
      totalData += packet.buf->computeChainDataLength();
    }
  }
};

} // namespace quic
