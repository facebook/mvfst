/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <folly/portability/GTest.h>
#include <quic/common/test/TestUtils.h>
#include <quic/dsr/Scheduler.h>
#include <quic/dsr/test/Mocks.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <algorithm>

namespace quic::test {

class DSRCommonTestFixture : public testing::Test {
 public:
  DSRCommonTestFixture()
      : conn_(FizzServerQuicHandshakeContext::Builder().build()),
        scheduler_(conn_),
        aead_(createNoOpAead()) {
    ON_CALL(sender_, addSendInstruction(testing::_))
        .WillByDefault(testing::Invoke([&](const SendInstruction&) {
          instructionCounter_++;
          return true;
        }));
    ON_CALL(sender_, flush()).WillByDefault(testing::Return(true));
  }

 protected:
  void prepareFlowControlAndStreamLimit() {
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn_.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn_.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn_.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
  }

  StreamId prepareOneStream(size_t bufMetaLength = 1000) {
    conn_.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn_.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
    auto id = conn_.streamManager->createNextBidirectionalStream().value()->id;
    auto stream = conn_.streamManager->findStream(id);
    writeDataToQuicStream(
        *stream,
        folly::IOBuf::copyBuffer("MetroCard Customer Claims"),
        false /* eof */);
    BufferMeta bufMeta(bufMetaLength);
    writeBufMetaToQuicStream(*stream, bufMeta, true /* eof */);
    return id;
  }

  bool verifyAllOutstandingsAreDSR() const {
    return std::all_of(
        conn_.outstandings.packets.begin(),
        conn_.outstandings.packets.end(),
        [](const OutstandingPacket& packet) { return packet.isDSRPacket; });
  }

 protected:
  QuicServerConnectionState conn_;
  DSRStreamFrameScheduler scheduler_;
  std::unique_ptr<Aead> aead_;
  MockDSRPacketizationRequestSender sender_;
  size_t instructionCounter_{0};
};
} // namespace quic::test
