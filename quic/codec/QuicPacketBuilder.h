/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Portability.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/QuicInteger.h>
#include <quic/codec/Types.h>
#include <quic/common/BufUtil.h>
#include <quic/handshake/HandshakeLayer.h>

namespace quic {

// maximum length of packet length.
constexpr auto kMaxPacketLenSize = sizeof(uint16_t);

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

// TODO: i'm sure this isn't the optimal value:
// Appender growth byte size for in PacketBuilder:
constexpr size_t kAppenderGrowthSize = 100;

class PacketBuilderInterface {
 public:
  virtual ~PacketBuilderInterface() = default;

  // TODO: Temporarly let this interface be reusable across different concrete
  // builder types. But this isn't optimized for builder that writes both header
  // and body into a continuous memory.
  struct Packet {
    RegularQuicWritePacket packet;
    Buf header;
    Buf body;

    Packet(RegularQuicWritePacket packetIn, Buf headerIn, Buf bodyIn)
        : packet(std::move(packetIn)),
          header(std::move(headerIn)),
          body(std::move(bodyIn)) {}
  };

  FOLLY_NODISCARD virtual uint32_t remainingSpaceInPkt() const = 0;

  // Functions to write bytes to the packet
  virtual void writeBE(uint8_t data) = 0;
  virtual void writeBE(uint16_t data) = 0;
  virtual void writeBE(uint64_t data) = 0;
  virtual void write(const QuicInteger& quicInteger) = 0;
  virtual void appendBytes(PacketNum value, uint8_t byteNumber) = 0;
  virtual void
  appendBytes(BufAppender& appender, PacketNum value, uint8_t byteNumber) = 0;
  virtual void
  appendBytes(BufWriter& writer, PacketNum value, uint8_t byteNumber) = 0;
  virtual void insert(std::unique_ptr<folly::IOBuf> buf) = 0;
  virtual void insert(std::unique_ptr<folly::IOBuf> buf, size_t limit) = 0;
  virtual void insert(const BufQueue& buf, size_t limit) = 0;
  virtual void push(const uint8_t* data, size_t len) = 0;

  // Append a frame to the packet.
  virtual void appendFrame(QuicWriteFrame frame) = 0;

  // Returns the packet header for the current packet.
  FOLLY_NODISCARD virtual const PacketHeader& getPacketHeader() const = 0;

  virtual void setCipherOverhead(uint8_t overhead) = 0;

  /**
   * Whether the packet builder is able to build a packet. This should be
   * checked right after the creation of a packet builder object.
   */
  FOLLY_NODISCARD virtual bool canBuildPacket() const noexcept = 0;

  /**
   * Return an estimated header bytes count.
   *
   * For short header, this is the exact header bytes. For long header, since
   * the writing of packet length and packet number field are deferred to the
   * buildPacket() call, this is an estimate header bytes count that's the sum
   * of header bytes already written, the maximum possible packet length field
   * bytes count and packet number field bytes count.
   */
  FOLLY_NODISCARD virtual uint32_t getHeaderBytes() const = 0;

  FOLLY_NODISCARD virtual bool hasFramesPending() const = 0;

  virtual Packet buildPacket() && = 0;
};

/**
 * Build packet into user provided IOBuf
 */
class InplaceQuicPacketBuilder final : public PacketBuilderInterface {
 public:
  ~InplaceQuicPacketBuilder() override = default;

  explicit InplaceQuicPacketBuilder(
      folly::IOBuf& iobuf,
      uint32_t remainingBytes,
      PacketHeader header,
      PacketNum largestAckedPacketNum);

  // PacketBuilderInterface
  FOLLY_NODISCARD uint32_t remainingSpaceInPkt() const override;

  void writeBE(uint8_t data) override;
  void writeBE(uint16_t data) override;
  void writeBE(uint64_t data) override;
  void write(const QuicInteger& quicInteger) override;
  void appendBytes(PacketNum value, uint8_t byteNumber) override;
  void appendBytes(BufAppender&, PacketNum, uint8_t) override {
    CHECK(false) << "Invalid appender";
  }
  void appendBytes(BufWriter& writer, PacketNum value, uint8_t byteNumber)
      override;
  void insert(std::unique_ptr<folly::IOBuf> buf) override;
  void insert(std::unique_ptr<folly::IOBuf> buf, size_t limit) override;
  void insert(const BufQueue& buf, size_t limit) override;
  void push(const uint8_t* data, size_t len) override;

  void appendFrame(QuicWriteFrame frame) override;
  FOLLY_NODISCARD const PacketHeader& getPacketHeader() const override;

  PacketBuilderInterface::Packet buildPacket() && override;

  FOLLY_NODISCARD bool canBuildPacket() const noexcept override;

  void setCipherOverhead(uint8_t overhead) noexcept override;

  FOLLY_NODISCARD uint32_t getHeaderBytes() const override;

  FOLLY_NODISCARD bool hasFramesPending() const override;

 private:
  folly::IOBuf& iobuf_;
  BufWriter bufWriter_;
  uint32_t remainingBytes_;
  RegularQuicWritePacket packet_;
  uint32_t cipherOverhead_{0};
  folly::Optional<PacketNumEncodingResult> packetNumberEncoding_;
  // The offset in the IOBuf writable area to write Packet Length.
  size_t packetLenOffset_{0};
  // The offset in the IOBuf writable area to write Packet Number.
  size_t packetNumOffset_{0};
  // The position to write body. This is only for byte counting purpose.
  uint8_t* bodyStart_{nullptr};
};

/**
 * Build packet into IOBufs created by Builder
 */
class RegularQuicPacketBuilder final : public PacketBuilderInterface {
 public:
  ~RegularQuicPacketBuilder() override = default;

  RegularQuicPacketBuilder(RegularQuicPacketBuilder&&) = default;

  using Packet = PacketBuilderInterface::Packet;

  RegularQuicPacketBuilder(
      uint32_t remainingBytes,
      PacketHeader header,
      PacketNum largestAckedPacketNum);

  FOLLY_NODISCARD uint32_t getHeaderBytes() const override;

  // PacketBuilderInterface
  FOLLY_NODISCARD uint32_t remainingSpaceInPkt() const override;

  void writeBE(uint8_t data) override;
  void writeBE(uint16_t data) override;
  void writeBE(uint64_t data) override;
  void write(const QuicInteger& quicInteger) override;
  void appendBytes(PacketNum value, uint8_t byteNumber) override;
  void appendBytes(BufAppender& appender, PacketNum value, uint8_t byteNumber)
      override;
  void appendBytes(BufWriter&, PacketNum, uint8_t) override {
    CHECK(false) << "Invalid BufWriter";
  }
  void insert(std::unique_ptr<folly::IOBuf> buf) override;
  void insert(std::unique_ptr<folly::IOBuf> buf, size_t limit) override;
  void insert(const BufQueue& buf, size_t limit) override;

  void push(const uint8_t* data, size_t len) override;

  void appendFrame(QuicWriteFrame frame) override;
  FOLLY_NODISCARD const PacketHeader& getPacketHeader() const override;

  Packet buildPacket() && override;
  /**
   * Whether the packet builder is able to build a packet. This should be
   * checked right after the creation of a packet builder object.
   */
  FOLLY_NODISCARD bool canBuildPacket() const noexcept override;

  void setCipherOverhead(uint8_t overhead) noexcept override;

  FOLLY_NODISCARD bool hasFramesPending() const override;

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
  std::unique_ptr<folly::IOBuf> header_;
  std::unique_ptr<folly::IOBuf> body_;
  BufAppender headerAppender_;
  BufAppender bodyAppender_;

  uint32_t cipherOverhead_{0};
  folly::Optional<PacketNumEncodingResult> packetNumberEncoding_;
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
  std::unique_ptr<folly::IOBuf> data_;
};

class StatelessResetPacketBuilder {
 public:
  StatelessResetPacketBuilder(
      uint16_t maxPacketSize,
      const StatelessResetToken& resetToken);

  Buf buildPacket() &&;

 private:
  std::unique_ptr<folly::IOBuf> data_;
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

  FOLLY_NODISCARD uint32_t remainingSpaceInPkt() const override {
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

  void appendBytes(BufAppender& appender, PacketNum value, uint8_t byteNumber)
      override {
    builder.appendBytes(appender, value, byteNumber);
  }

  void appendBytes(BufWriter& writer, PacketNum value, uint8_t byteNumber)
      override {
    builder.appendBytes(writer, value, byteNumber);
  }

  void insert(std::unique_ptr<folly::IOBuf> buf) override {
    builder.insert(std::move(buf));
  }

  void insert(std::unique_ptr<folly::IOBuf> buf, size_t limit) override {
    builder.insert(std::move(buf), limit);
  }

  void insert(const BufQueue& buf, size_t limit) override {
    builder.insert(buf, limit);
  }

  void appendFrame(QuicWriteFrame frame) override {
    builder.appendFrame(std::move(frame));
  }

  void push(const uint8_t* data, size_t len) override {
    builder.push(data, len);
  }

  FOLLY_NODISCARD const PacketHeader& getPacketHeader() const override {
    return builder.getPacketHeader();
  }

  PacketBuilderInterface::Packet buildPacket() && override {
    return std::move(builder).buildPacket();
  }

  void setCipherOverhead(uint8_t overhead) noexcept override {
    builder.setCipherOverhead(overhead);
  }

  FOLLY_NODISCARD bool canBuildPacket() const noexcept override {
    return builder.canBuildPacket();
  };

  FOLLY_NODISCARD uint32_t getHeaderBytes() const override {
    return builder.getHeaderBytes();
  }

  FOLLY_NODISCARD bool hasFramesPending() const override {
    return builder.hasFramesPending();
  }

 private:
  PacketBuilderInterface& builder;
  uint32_t diff;
};
} // namespace quic
