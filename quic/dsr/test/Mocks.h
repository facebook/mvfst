/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
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
  MOCK_METHOD(bool, addSendInstruction, (const SendInstruction&));
  MOCK_METHOD(bool, flush, ());
  MOCK_METHOD(void, release, ());
};

} // namespace quic::test
