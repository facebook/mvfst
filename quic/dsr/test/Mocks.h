/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/dsr/DSRPacketizationRequestSender.h>

namespace quic {
struct SendInstruction;
}

namespace quic::test {

class MockDSRPacketizationRequestSender : public DSRPacketizationRequestSender {
 public:
  MOCK_METHOD1(addSendInstruction, bool(const SendInstruction&));
  MOCK_METHOD0(flush, bool());
  MOCK_METHOD0(release, void());
};

} // namespace quic::test
