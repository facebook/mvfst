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
  NetworkData() = default;
  NetworkData(Buf&& buf, const TimePoint& receiveTime)
      : receiveTimePoint_(receiveTime) {
    if (buf) {
      totalData_ = buf->computeChainDataLength();
      packets_.emplace_back(std::move(buf));
    }
  }

  NetworkData(
      std::vector<Buf>&& packetBufs,
      const TimePoint& receiveTimePointIn)
      : receiveTimePoint_(receiveTimePointIn),
        packets_([&packetBufs]() {
          std::vector<ReceivedPacket> result;
          result.reserve(packetBufs.size());
          for (auto& packetBuf : packetBufs) {
            result.emplace_back(std::move(packetBuf));
          }
          return result;
        }()),
        totalData_([this]() {
          size_t result = 0;
          for (const auto& packet : packets_) {
            result += packet.buf->computeChainDataLength();
          }
          return result;
        }()) {}

  void reserve(size_t size) {
    packets_.reserve(size);
  }

  void addPacket(ReceivedPacket&& packetIn) {
    packets_.emplace_back(std::move(packetIn));
  }

  [[nodiscard]] const std::vector<ReceivedPacket>& getPackets() const {
    return packets_;
  }

  std::vector<ReceivedPacket> movePackets() && {
    return std::move(packets_);
  }

  void setReceiveTimePoint(const TimePoint& receiveTimePointIn) {
    receiveTimePoint_ = receiveTimePointIn;
  }

  [[nodiscard]] TimePoint getReceiveTimePoint() const {
    return receiveTimePoint_;
  }

  void setTotalData(const size_t totalDataIn) {
    totalData_ = totalDataIn;
  }

  [[nodiscard]] size_t getTotalData() const {
    return totalData_;
  }

  std::unique_ptr<folly::IOBuf> moveAllData() && {
    std::unique_ptr<folly::IOBuf> buf;
    for (auto& packet : packets_) {
      if (buf) {
        buf->prependChain(std::move(packet.buf));
      } else {
        buf = std::move(packet.buf);
      }
    }
    return buf;
  }

 private:
  TimePoint receiveTimePoint_;
  std::vector<ReceivedPacket> packets_;
  size_t totalData_{0};
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
