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
  struct Timings {
    // Legacy Receive TimePoint.
    //
    // This TimePoint is being deprecated in favor of having TimePoints that are
    // named specifically for the timing event being tracked.
    //
    // The meaning of this TimePoint varies by transport implementation and
    // settings: it can be the time when recv() started or completed, the socket
    // RX timestamp for this packet or another packet received during the same
    // call to recv*(), or something else entirely.
    //
    // TODO(bschlinker): Complete deprecation
    TimePoint receiveTimePoint;
  };

  ReceivedPacket() = default;
  explicit ReceivedPacket(Buf&& bufIn) : buf(std::move(bufIn)) {}

  Buf buf;
  Timings timings;
};

struct NetworkData {
  NetworkData() = default;
  NetworkData(Buf&& buf, const TimePoint& receiveTimePointIn)
      : receiveTimePoint_(receiveTimePointIn) {
    if (buf) {
      totalData_ = buf->computeChainDataLength();
      packets_.emplace_back(std::move(buf));
      packets_.back().timings.receiveTimePoint = receiveTimePointIn;
    }
  }

  NetworkData(
      std::vector<Buf>&& packetBufs,
      const TimePoint& receiveTimePointIn)
      : receiveTimePoint_(receiveTimePointIn),
        packets_([&packetBufs, &receiveTimePointIn]() {
          std::vector<ReceivedPacket> result;
          result.reserve(packetBufs.size());
          for (auto& packetBuf : packetBufs) {
            result.emplace_back(std::move(packetBuf));
          }
          for (auto& packet : result) {
            packet.timings.receiveTimePoint = receiveTimePointIn;
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
    packets_.back().timings.receiveTimePoint = receiveTimePoint_;
    totalData_ += packets_.back().buf->computeChainDataLength();
  }

  [[nodiscard]] const std::vector<ReceivedPacket>& getPackets() const {
    return packets_;
  }

  std::vector<ReceivedPacket> movePackets() && {
    return std::move(packets_);
  }

  void setReceiveTimePoint(const TimePoint& receiveTimePointIn) {
    receiveTimePoint_ = receiveTimePointIn;
    for (auto& packet : packets_) {
      packet.timings.receiveTimePoint = receiveTimePointIn;
    }
  }

  [[nodiscard]] TimePoint getReceiveTimePoint() const {
    return receiveTimePoint_;
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
  size_t totalData{0};

  NetworkDataSingle() = default;

  explicit NetworkDataSingle(ReceivedPacket&& packetIn)
      : packet(std::move(packetIn)) {
    if (packet.buf) {
      totalData += packet.buf->computeChainDataLength();
    }
  }

  // TODO(bschlinker): Deprecate
  NetworkDataSingle(
      ReceivedPacket&& packetIn,
      const TimePoint& receiveTimePointIn)
      : packet(std::move(packetIn)) {
    packet.timings.receiveTimePoint = receiveTimePointIn;
    if (packet.buf) {
      totalData += packet.buf->computeChainDataLength();
    }
  }
};

} // namespace quic
