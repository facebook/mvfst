/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/dsr/backend/test/TestUtils.h>
#include <quic/tools/tperf/TperfDSRSender.h>

namespace quic {

TperfDSRSender::TperfDSRSender(uint64_t blockSize, folly::AsyncUDPSocket& sock)
    : blockSize_(blockSize), sock_(sock) {}

bool TperfDSRSender::addSendInstruction(const SendInstruction& instruction) {
  instructions_.push_back(instruction);
  return true;
}

bool TperfDSRSender::flush() {
  // TODO remove this when we make instructions match the request.
  auto& firstInstruction = instructions_.front();
  CipherBuilder builder;
  auto cipherPair = builder.buildCiphers(
      fizz::TrafficKey{
          std::move(firstInstruction.trafficKey.key),
          std::move(firstInstruction.trafficKey.iv)},
      firstInstruction.cipherSuite,
      firstInstruction.packetProtectionKey->clone());

  RequestGroup prs{
      firstInstruction.dcid,
      firstInstruction.scid,
      firstInstruction.clientAddress,
      &cipherPair,
      {}};
  for (const auto& instruction : instructions_) {
    prs.requests.push_back(
        test::sendInstructionToPacketizationRequest(instruction));
  }
  auto written =
      writePacketsGroup(sock_, prs, [=](const PacketizationRequest& req) {
        auto buf = folly::IOBuf::createChain(req.len, blockSize_);
        auto curBuf = buf.get();
        do {
          curBuf->append(curBuf->capacity());
          curBuf = curBuf->next();
        } while (curBuf != buf.get());
        return buf;
      });
  instructions_.clear();
  return written.packetsSent > 0;
}

void TperfDSRSender::release() {}
} // namespace quic
