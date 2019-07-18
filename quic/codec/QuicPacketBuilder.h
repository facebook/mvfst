/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/codec/PacketNumber.h>
#include <quic/codec/QuicInteger.h>
#include <quic/codec/Types.h>
#include <quic/handshake/HandshakeLayer.h>

namespace quic {

// We reserve 2 bytes for packet length in the long headers
constexpr auto kReservedPacketLenSize = sizeof(uint16_t);

// We reserve 4 bytes for packet number in the long headers.
constexpr auto kReservedPacketNumSize = kMaxPacketNumEncodingSize;

// Note a full PacketNum has 64 bits, but LongHeader only uses 32 bits of them
// This is based on Draft-22
constexpr auto kLongHeaderHeaderSize = sizeof(uint8_t) /* Type bytes */ +
    sizeof(QuicVersionType) /* Version */ +
    2 * sizeof(uint8_t) /* DCIL + SCIL */ +
    kDefaultConnectionIdSize * 2 /* 2 connection IDs */ +
    kReservedPacketLenSize /* minimal size of length */ +
    kReservedPacketNumSize /* packet number */;

// A possible cipher overhead. The real overhead depends on the AEAD we will
// use. But we need a ball-park value when deciding if we should schedule a
// write.
constexpr auto kCipherOverheadHeuristic = 16;

// TODO: i'm sure this isn't the optimal value:
// IOBufQueue growth byte size for in PacketBuilder:
constexpr size_t kAppenderGrowthSize = 100;

class PacketBuilderInterface {
 public:
  virtual ~PacketBuilderInterface() = default;

  virtual uint32_t remainingSpaceInPkt() const = 0;

  // Functions to write bytes to the packet
  virtual void writeBE(uint8_t data) = 0;
  virtual void writeBE(uint16_t data) = 0;
  virtual void writeBE(uint64_t data) = 0;
  virtual void write(const QuicInteger& quicInteger) = 0;
  virtual void appendBytes(PacketNum value, uint8_t byteNumber) = 0;
  virtual void appendBytes(
      folly::io::QueueAppender& appender,
      PacketNum value,
      uint8_t byteNumber) = 0;
  virtual void insert(std::unique_ptr<folly::IOBuf> buf) = 0;
  virtual void push(const uint8_t* data, size_t len) = 0;

  // Append a frame to the packet.
  virtual void appendFrame(QuicWriteFrame frame) = 0;

  // Returns the packet header for the current packet.
  virtual const PacketHeader& getPacketHeader() const = 0;

  // Horrible hack, remove when we stop having to support MVFST_OLD
  virtual QuicVersion getVersion() const {
    return QuicVersion::MVFST;
  }
};

class RegularQuicPacketBuilder : public PacketBuilderInterface {
 public:
  ~RegularQuicPacketBuilder() override = default;

  RegularQuicPacketBuilder(RegularQuicPacketBuilder&&) = default;

  struct Packet {
    RegularQuicWritePacket packet;
    Buf header;
    Buf body;

    Packet(RegularQuicWritePacket packetIn, Buf headerIn, Buf bodyIn)
        : packet(std::move(packetIn)),
          header(std::move(headerIn)),
          body(std::move(bodyIn)) {}
  };

  RegularQuicPacketBuilder(
      uint32_t remainingBytes,
      PacketHeader header,
      PacketNum largestAckedPacketNum,
      QuicVersion version = QuicVersion::MVFST_OLD);

  uint32_t getHeaderBytes() const;

  // PacketBuilderInterface
  uint32_t remainingSpaceInPkt() const override;

  void writeBE(uint8_t data) override;
  void writeBE(uint16_t data) override;
  void writeBE(uint64_t data) override;
  void write(const QuicInteger& quicInteger) override;
  void appendBytes(PacketNum value, uint8_t byteNumber) override;
  void appendBytes(
      folly::io::QueueAppender& appender,
      PacketNum value,
      uint8_t byteNumber) override;
  void insert(std::unique_ptr<folly::IOBuf> buf) override;
  void push(const uint8_t* data, size_t len) override;

  void appendFrame(QuicWriteFrame frame) override;
  const PacketHeader& getPacketHeader() const override;

  Packet buildPacket() &&;
  /**
   * Whether the packet builder is able to build a packet. This should be
   * checked right after the creation of a packet builder object.
   */
  bool canBuildPacket() const noexcept;

  void setCipherOverhead(uint8_t overhead) noexcept;

  QuicVersion getVersion() const override;

 private:
  void writeHeaderBytes(PacketNum largestAckedPacketNum);
  void encodeLongHeader(
      const LongHeader& longHeader,
      PacketNum largestAckedPacketNum);
  void encodeShortHeader(
      const ShortHeader& shortHeader,
      PacketNum largestAckedPacketNum);

 private:
  uint32_t remainingBytes_;
  RegularQuicWritePacket packet_;
  std::vector<QuicWriteFrame> quicFrames_;
  folly::IOBufQueue header_{folly::IOBufQueue::cacheChainLength()};
  folly::IOBufQueue outputQueue_{folly::IOBufQueue::cacheChainLength()};
  folly::io::QueueAppender headerAppender_;
  folly::io::QueueAppender bodyAppender_;
  uint32_t cipherOverhead_{0};
  folly::Optional<PacketNumEncodingResult> packetNumberEncoding_;
  QuicVersion version_;
};

class VersionNegotiationPacketBuilder {
 public:
  explicit VersionNegotiationPacketBuilder(
      ConnectionId sourceConnectionId,
      ConnectionId destinationConnectionId,
      const std::vector<QuicVersion>& versions);

  virtual ~VersionNegotiationPacketBuilder() = default;

  uint32_t remainingSpaceInPkt();
  std::pair<VersionNegotiationPacket, Buf> buildPacket() &&;
  /**
   * Whether the packet builder is able to build a packet. This should be
   * checked right after the creation of a packet builder object.
   */
  bool canBuildPacket() const noexcept;

 private:
  void writeVersionNegotiationPacket(const std::vector<QuicVersion>& versions);

  uint8_t generateRandomPacketType() const;

 private:
  uint32_t remainingBytes_;
  VersionNegotiationPacket packet_;
  folly::IOBufQueue outputQueue_{folly::IOBufQueue::cacheChainLength()};
  folly::io::QueueAppender appender_;
};

class StatelessResetPacketBuilder {
 public:
  StatelessResetPacketBuilder(
      uint16_t maxPacketSize,
      const StatelessResetToken& resetToken);

  Buf buildPacket() &&;

 private:
  folly::IOBufQueue outputQueue_{folly::IOBufQueue::cacheChainLength()};
};

/**
 * A PacketBuilder that wraps in another PacketBuilder that may have a different
 * writableBytes limit. The minimum between the limit will be used to limit the
 * packet it can build.
 */
class PacketBuilderWrapper : public PacketBuilderInterface {
 public:
  ~PacketBuilderWrapper() override = default;

  PacketBuilderWrapper(
      PacketBuilderInterface& builderIn,
      uint32_t writableBytes)
      : builder(builderIn),
        diff(
            writableBytes > builder.remainingSpaceInPkt()
                ? 0
                : builder.remainingSpaceInPkt() - writableBytes) {}

  uint32_t remainingSpaceInPkt() const override {
    return builder.remainingSpaceInPkt() > diff
        ? builder.remainingSpaceInPkt() - diff
        : 0;
  }

  void write(const QuicInteger& quicInteger) override {
    builder.write(quicInteger);
  }

  void writeBE(uint8_t value) override {
    builder.writeBE(value);
  }

  void writeBE(uint16_t value) override {
    builder.writeBE(value);
  }

  void writeBE(uint64_t value) override {
    builder.writeBE(value);
  }

  void appendBytes(PacketNum value, uint8_t byteNumber) override {
    builder.appendBytes(value, byteNumber);
  }

  void appendBytes(
      folly::io::QueueAppender& appender,
      PacketNum value,
      uint8_t byteNumber) override {
    builder.appendBytes(appender, value, byteNumber);
  }

  void insert(std::unique_ptr<folly::IOBuf> buf) override {
    builder.insert(std::move(buf));
  }

  void appendFrame(QuicWriteFrame frame) override {
    builder.appendFrame(std::move(frame));
  }

  void push(const uint8_t* data, size_t len) override {
    builder.push(data, len);
  }

  const PacketHeader& getPacketHeader() const override {
    return builder.getPacketHeader();
  }

  QuicVersion getVersion() const override {
    return builder.getVersion();
  }

 private:
  PacketBuilderInterface& builder;
  uint32_t diff;
};
} // namespace quic
