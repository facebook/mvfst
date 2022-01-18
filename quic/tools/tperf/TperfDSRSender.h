/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/SocketAddress.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/io/async/EventBase.h>
#include <quic/dsr/DSRPacketizationRequestSender.h>
#include <quic/dsr/Types.h>
#include <vector>

#pragma once

namespace quic {

/**
 * This is a implementtion of DSRPacketizationRequestSender that directly calls
 * the backend writePacketsGroup API within itself. It's completely in-process
 * with no RPC involved. It also shares the AsyncUDPSockets with the
 * TperfServer' QuicServerTransports instead of creating one within itself.
 *
 * The bytes it sends out are random.
 *
 * The main purpose of this sender is to sanity test DSR APIs in QUIC transport.
 */
class TperfDSRSender : public DSRPacketizationRequestSender {
 public:
  explicit TperfDSRSender(uint64_t blockSize, folly::AsyncUDPSocket& sock);

  bool addSendInstruction(const SendInstruction&) override;

  bool flush() override;

  void release() override;

 private:
  std::vector<SendInstruction> instructions_;
  uint64_t blockSize_;
  folly::AsyncUDPSocket& sock_;
};

} // namespace quic
