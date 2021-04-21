/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/dsr/DSRPacketizationRequestSender.h>
#include <quic/dsr/PacketBuilder.h>

namespace quic::test {

class MockDSRPacketBuilder : public DSRPacketBuilderBase {
 public:
  GMOCK_METHOD0_(, noexcept, , remainingSpaceNonConst, size_t());

  size_t remainingSpace() const noexcept override {
    return const_cast<MockDSRPacketBuilder&>(*this).remainingSpaceNonConst();
  }

  MOCK_METHOD2(addSendInstructionPtr, void(const SendInstruction*, uint32_t));

  void addSendInstruction(
      SendInstruction instruction,
      uint32_t streamEncodedSize) override {
    addSendInstructionPtr(&instruction, streamEncodedSize);
  }
};

class MockDSRPacketizationRequestSender : public DSRPacketizationRequestSender {
 public:
  MOCK_METHOD1(addSendInstruction, bool(const SendInstruction&));
  MOCK_METHOD0(flush, bool());
  MOCK_METHOD0(release, void());
};

} // namespace quic::test
