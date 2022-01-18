/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

namespace quic {

struct SendInstruction;

class DSRPacketizationRequestSender {
 public:
  virtual ~DSRPacketizationRequestSender() = default;

  /**
   * addSendInstruction() adds a single SendInstruction to the packetization
   * request sender. The sender can accumulate the instructions then send them
   * out as a batch when flush() is called.
   */
  virtual bool addSendInstruction(const SendInstruction&) = 0;

  // flush() tells the sender that it can send out packetization requests
  virtual bool flush() = 0;

  /**
   * release() tells the sender that it should release resources.
   * After release() is called, the sender should not receive any additional
   * instructions
   */
  virtual void release() = 0;
};

} // namespace quic
