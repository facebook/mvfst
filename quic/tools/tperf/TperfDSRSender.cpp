/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/dsr/backend/test/TestUtils.h>
#include <quic/tools/tperf/TperfDSRSender.h>

namespace quic {

TperfDSRSender::TperfDSRSender(BufPtr sendBuf, QuicAsyncUDPSocket& sock)
    : sock_(sock), buf_(std::move(sendBuf)) {}

bool TperfDSRSender::addSendInstruction(const SendInstruction& instruction) {
  instructions_.push_back(instruction);
  return true;
}

void TperfDSRSender::setCipherInfo(CipherInfo info) {
  CipherBuilder builder;
  cipherPair_ = builder.buildCiphers(
      fizz::TrafficKey{
          .key = std::move(info.trafficKey.key),
          .iv = std::move(info.trafficKey.iv)},
      info.cipherSuite,
      std::move(info.packetProtectionKey));
}

bool TperfDSRSender::flush() {
  auto& firstInstruction = instructions_.front();
  RequestGroup prs{
      .dcid = firstInstruction.dcid,
      .scid = firstInstruction.scid,
      .clientAddress = firstInstruction.clientAddress,
      .cipherPair = &cipherPair_,
      .requests = {}};
  prs.requests.reserve(instructions_.size());
  for (const auto& instruction : instructions_) {
    prs.requests.push_back(
        test::sendInstructionToPacketizationRequest(instruction));
  }
  quic::UdpSocketPacketGroupWriter packetGroupWriter(sock_, prs.clientAddress);
  auto written = packetGroupWriter.writePacketsGroup(
      prs, [=, this](const PacketizationRequest& req) {
        BufPtr buf;
        uint64_t remainingLen = req.len;
        do {
          buf = buf_->clone();
          uint64_t appendLen =
              std::min<uint64_t>(remainingLen, buf->capacity());
          buf->append(appendLen);
          remainingLen -= appendLen;
        } while (buf->length() < req.len);
        return buf;
      });
  instructions_.clear();
  return written.packetsSent > 0;
}

void TperfDSRSender::release() {}
} // namespace quic
