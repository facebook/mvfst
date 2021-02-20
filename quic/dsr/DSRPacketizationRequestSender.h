/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/dsr/Types.h>

namespace quic {

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
};

} // namespace quic
