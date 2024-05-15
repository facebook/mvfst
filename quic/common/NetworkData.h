/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <quic/QuicConstants.h>
#include <quic/common/BufUtil.h>
#include <quic/common/TimePoints.h>

#include <memory>
#include <vector>

namespace quic {

/**
 * Received UDP packet with timings.
 *
 * A single UDP packet can contain multiple QUIC packets due to UDP packet
 * coalescing (see RFC 9000, section 12.2). When invoked, this function attempts
 * to transform the UDP packet data into one or more QUIC packets.
 */
struct ReceivedUdpPacket {
  struct Timings {
    /**
     * Socket timestamp with additional information.
     */
    struct SocketTimestampExt {
      // raw duration read from the socket
      std::chrono::nanoseconds rawDuration{};

      // duration transformed into SystemClock TimePoint
      chrono::SystemClockTimePointExt systemClock;
    };

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

    // Socket timestamps, when available.
    folly::Optional<SocketTimestampExt> maybeSoftwareTs;
  };

  ReceivedUdpPacket() = default;
  explicit ReceivedUdpPacket(Buf&& bufIn) : buf(std::move(bufIn)) {}
  ReceivedUdpPacket(Buf&& bufIn, Timings timingsIn, uint8_t tosValueIn)
      : buf(std::move(bufIn)),
        timings(std::move(timingsIn)),
        tosValue(tosValueIn) {}

  BufQueue buf;
  Timings timings;

  // ToS / TClass value
  uint8_t tosValue{0};
};

struct NetworkData {
  NetworkData() = default;
  NetworkData(
      Buf&& buf,
      const TimePoint& receiveTimePointIn,
      uint8_t tosValueIn)
      : receiveTimePoint_(receiveTimePointIn) {
    if (buf) {
      totalData_ = buf->computeChainDataLength();
      packets_.emplace_back(std::move(buf));
      packets_.back().timings.receiveTimePoint = receiveTimePointIn;
      packets_.back().tosValue = tosValueIn;
    }
  }

  explicit NetworkData(ReceivedUdpPacket&& udpPacket)
      : receiveTimePoint_(udpPacket.timings.receiveTimePoint) {
    totalData_ = udpPacket.buf.chainLength();
    packets_.push_back(std::move(udpPacket));
  }

  NetworkData(
      std::vector<Buf>&& packetBufs,
      const TimePoint& receiveTimePointIn)
      : receiveTimePoint_(receiveTimePointIn),
        packets_([&packetBufs, &receiveTimePointIn]() {
          std::vector<ReceivedUdpPacket> result;
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
            result += packet.buf.chainLength();
          }
          return result;
        }()) {}

  void reserve(size_t size) {
    packets_.reserve(size);
  }

  void addPacket(ReceivedUdpPacket&& packetIn) {
    packets_.emplace_back(std::move(packetIn));
    packets_.back().timings.receiveTimePoint = receiveTimePoint_;
    totalData_ += packets_.back().buf.chainLength();
  }

  [[nodiscard]] const std::vector<ReceivedUdpPacket>& getPackets() const {
    return packets_;
  }

  std::vector<ReceivedUdpPacket> movePackets() && {
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
        buf->prependChain(packet.buf.move());
      } else {
        buf = packet.buf.move();
      }
    }
    return buf;
  }

 private:
  TimePoint receiveTimePoint_;
  std::vector<ReceivedUdpPacket> packets_;
  size_t totalData_{0};
};

} // namespace quic
