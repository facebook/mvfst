/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/common/test/TestUtils.h>

namespace quic {
namespace test {

class MockConnectionIdAlgo : public ConnectionIdAlgo {
 public:
  MOCK_METHOD((bool), canParseNonConst, (const ConnectionId& id), (noexcept));
  MOCK_METHOD(
      (folly::Expected<ServerConnectionIdParams, QuicInternalException>),
      parseConnectionId,
      (const ConnectionId&),
      (noexcept));
  MOCK_METHOD(
      (folly::Expected<ConnectionId, QuicInternalException>),
      encodeConnectionId,
      (const ServerConnectionIdParams&),
      (noexcept));

  bool canParse(const ConnectionId& id) const noexcept override {
    return const_cast<MockConnectionIdAlgo&>(*this).canParseNonConst(id);
  }
};

class MockQuicPacketBuilder : public PacketBuilderInterface {
 public:
  // override method with unique_ptr since gmock doesn't support it
  void insert(std::unique_ptr<folly::IOBuf> buf) override {
    _insert(buf);
  }

  void insert(std::unique_ptr<folly::IOBuf> buf, size_t limit) override {
    _insert(buf, limit);
  }
  MOCK_METHOD(void, appendFrame, (QuicWriteFrame));
  MOCK_METHOD(void, _insert, (std::unique_ptr<folly::IOBuf>&));
  MOCK_METHOD(void, _insert, (std::unique_ptr<folly::IOBuf>&, size_t));
  MOCK_METHOD(void, insert, (const BufQueue&, size_t));
  MOCK_METHOD(void, push, (const uint8_t*, size_t));
  MOCK_METHOD(void, write, (const QuicInteger&));

  MOCK_METHOD(uint32_t, remainingSpaceInPkt, (), (const));
  MOCK_METHOD(const PacketHeader&, getPacketHeader, (), (const));

  MOCK_METHOD(void, writeBEUint8, (uint8_t));
  MOCK_METHOD(void, writeBEUint16, (uint16_t));
  MOCK_METHOD(void, writeBEUint64, (uint16_t));

  MOCK_METHOD(void, appendBytes, (PacketNum, uint8_t));
  MOCK_METHOD(
      void,
      appendBytesWithAppender,
      (BufAppender&, PacketNum, uint8_t));
  MOCK_METHOD(void, appendBytesWithBufWriter, (BufWriter&, PacketNum, uint8_t));
  MOCK_METHOD(void, accountForCipherOverhead, (uint8_t), (noexcept));
  MOCK_METHOD(bool, canBuildPacketNonConst, (), (noexcept));
  MOCK_METHOD(uint32_t, getHeaderBytes, (), (const));
  MOCK_METHOD(bool, hasFramesPending, (), (const));
  MOCK_METHOD(void, releaseOutputBufferMock, ());
  MOCK_METHOD(void, encodePacketHeader, ());

  void releaseOutputBuffer() && override {
    releaseOutputBufferMock();
  }

  bool canBuildPacket() const noexcept override {
    return const_cast<MockQuicPacketBuilder&>(*this).canBuildPacketNonConst();
  }

  void appendBytes(
      BufAppender& appender,
      PacketNum packetNum,
      uint8_t byteNumber) override {
    appendBytesWithAppender(appender, packetNum, byteNumber);
  }

  void appendBytes(
      BufWriter& bufWriter,
      PacketNum packetNum,
      uint8_t byteNumber) override {
    appendBytesWithBufWriter(bufWriter, packetNum, byteNumber);
  }

  void writeBE(uint8_t value) override {
    writeBEUint8(value);
  }

  void writeBE(uint16_t value) override {
    writeBEUint16(value);
  }

  void writeBE(uint64_t value) override {
    writeBEUint64(value);
  }

  PacketBuilderInterface::Packet buildPacket() && override {
    CHECK(false) << "Use buildTestPacket()";
  }

  std::pair<RegularQuicWritePacket, Buf> buildTestPacket() && {
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
