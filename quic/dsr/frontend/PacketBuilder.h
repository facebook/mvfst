/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/PacketNumber.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/Types.h>
#include <quic/dsr/Types.h>

namespace quic {

struct DSRPacketBuilderBase {
  virtual ~DSRPacketBuilderBase() = default;
  virtual size_t remainingSpace() const noexcept = 0;
  virtual void addSendInstruction(SendInstruction&&, uint32_t) = 0;
};

/**
 * This is likely a bad name. The point of having a "Packet Builder" is to
 * create the OutstandingPacket when we send out send instructions.
 *
 * I do think from perf perspective we can do better than this in the future.
 */
class DSRPacketBuilder : public DSRPacketBuilderBase {
 public:
  explicit DSRPacketBuilder(
      size_t packetSize,
      ShortHeader header,
      PacketNum largestAckedPacketNum)
      : packetSize_(packetSize), packet_(std::move(header)) {
    updatePacketSizeWithHeader(largestAckedPacketNum);
  }

  void addSendInstruction(
      SendInstruction&& sendInstruction,
      uint32_t streamEncodedSize) override {
    CHECK(
        sendInstructions_.empty() ||
        sendInstructions_.back().streamId == sendInstruction.streamId);
    WriteStreamFrame frame = sendInstructionToWriteStreamFrame(sendInstruction);
    packet_.frames.push_back(frame);
    sendInstructions_.push_back(std::move(sendInstruction));
    packetSize_ -= streamEncodedSize;
    encodedSize_ += streamEncodedSize;
  }

  struct Packet {
    RegularQuicWritePacket packet;
    std::vector<SendInstruction> sendInstructions;
    uint32_t encodedSize;

    Packet(
        RegularQuicWritePacket pkt,
        std::vector<SendInstruction> instructions,
        uint32_t size)
        : packet(std::move(pkt)),
          sendInstructions(std::move(instructions)),
          encodedSize(size) {}
  };

  Packet buildPacket() && {
    CHECK(!sendInstructions_.empty());
    CHECK_EQ(sendInstructions_.size(), packet_.frames.size());
    return Packet(packet_, std::move(sendInstructions_), encodedSize_);
  }

  size_t remainingSpace() const noexcept override {
    return packetSize_;
  }

 private:
  void updatePacketSizeWithHeader(PacketNum largestAckedPacketNum) {
    auto shortHeader = packet_.header.asShort();
    CHECK(shortHeader);
    auto packetNumEncoding = encodePacketNumber(
        shortHeader->getPacketSequenceNum(), largestAckedPacketNum);
    auto connIdLen = shortHeader->getConnectionId().size();
    if (packetNumEncoding.length + connIdLen + 1 > packetSize_) {
      packetSize_ = 0;
      return;
    }
    auto headerSize = packetNumEncoding.length + connIdLen + 1;
    encodedSize_ += headerSize;
    packetSize_ -= headerSize;
  }

 private:
  size_t packetSize_;
  RegularQuicWritePacket packet_;
  std::vector<SendInstruction> sendInstructions_;
  uint32_t encodedSize_{0};
};

} // namespace quic
