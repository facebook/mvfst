/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/common/test/TestUtils.h>

namespace quic {
// Otherwise you won't be able to mock QuicPacketBuidlerBase::appendFrame()
std::ostream& operator<<(std::ostream& out, const QuicWriteFrame& /*rhs*/) {
  return out;
}
} // namespace quic

namespace quic {
namespace test {

class MockQuicPacketBuilder : public PacketBuilderInterface {
 public:
  // override method with unique_ptr since gmock doesn't support it
  void insert(std::unique_ptr<folly::IOBuf> buf) override {
    _insert(buf);
  }
  MOCK_METHOD1(appendFrame, void(QuicWriteFrame));
  MOCK_METHOD1(_insert, void(std::unique_ptr<folly::IOBuf>&));
  MOCK_METHOD2(push, void(const uint8_t*, size_t));
  MOCK_METHOD1(write, void(const QuicInteger&));

  GMOCK_METHOD0_(, const, , remainingSpaceInPkt, uint32_t());
  GMOCK_METHOD0_(, const, , getPacketHeader, const PacketHeader&());

  MOCK_METHOD1(writeBEUint8, void(uint8_t));
  MOCK_METHOD1(writeBEUint16, void(uint16_t));
  MOCK_METHOD1(writeBEUint64, void(uint16_t));

  MOCK_METHOD2(appendBytes, void(PacketNum, uint8_t));
  MOCK_METHOD3(appendBytes, void(BufAppender&, PacketNum, uint8_t));

  void writeBE(uint8_t value) override {
    writeBEUint8(value);
  }

  void writeBE(uint16_t value) override {
    writeBEUint16(value);
  }

  void writeBE(uint64_t value) override {
    writeBEUint64(value);
  }

  std::pair<RegularQuicWritePacket, Buf> buildPacket() && {
    ShortHeader header(
        ProtectionType::KeyPhaseZero, getTestConnectionId(), 0x01);
    RegularQuicWritePacket regularPacket(std::move(header));
    regularPacket.frames = std::move(frames_);
    return std::make_pair(std::move(regularPacket), std::move(data_));
  }

  std::pair<RegularQuicWritePacket, Buf> buildLongHeaderPacket() && {
    ConnectionId connId = getTestConnectionId();
    PacketNum packetNum = 10;
    LongHeader header(
        LongHeader::Types::Handshake,
        getTestConnectionId(1),
        connId,
        packetNum,
        QuicVersion::MVFST);
    RegularQuicWritePacket regularPacket(std::move(header));
    regularPacket.frames = std::move(frames_);
    return std::make_pair(std::move(regularPacket), std::move(data_));
  }

  RegularQuicWritePacket::Vec frames_;
  uint32_t remaining_{kDefaultUDPSendPacketLen};
  std::unique_ptr<folly::IOBuf> data_{folly::IOBuf::create(100)};
  BufAppender appender_{data_.get(), 100};
};
} // namespace test
} // namespace quic
