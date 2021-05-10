/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/dsr/frontend/PacketBuilder.h>

namespace quic::test {

class MockDSRPacketBuilder : public DSRPacketBuilderBase {
 public:
  GMOCK_METHOD0_(, noexcept, , remainingSpaceNonConst, size_t());

  size_t remainingSpace() const noexcept override {
    return const_cast<MockDSRPacketBuilder&>(*this).remainingSpaceNonConst();
  }

  MOCK_METHOD2(addSendInstruction, void(SendInstruction&&, uint32_t));
};

} // namespace quic::test
