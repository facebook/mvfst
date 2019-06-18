/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <folly/Random.h>
#include <folly/io/Cursor.h>
#include <folly/io/IOBufQueue.h>
#include <folly/io/async/test/MockAsyncUDPSocket.h>
#include <quic/api/QuicTransportBase.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/api/test/Mocks.h>
#include <quic/common/Timers.h>
#include <quic/common/test/TestUtils.h>
#include <quic/handshake/test/Mocks.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/test/Mocks.h>

using namespace folly;
using namespace folly::test;
using namespace testing;

namespace quic {
namespace test {

class TestQuicTransport
    : public QuicTransportBase,
      public std::enable_shared_from_this<TestQuicTransport> {
 public:
  TestQuicTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      ConnectionCallback& cb)
      : QuicTransportBase(evb, std::move(socket)) {
    setConnectionCallback(&cb);
    conn_ = std::make_unique<QuicServerConnectionState>();
    conn_->clientConnectionId = ConnectionId({9, 8, 7, 6});
    conn_->serverConnectionId = ConnectionId({1, 2, 3, 4});
    conn_->version = QuicVersion::MVFST;
    aead = test::createNoOpAead();
    headerCipher = test::createNoOpHeaderCipher();
  }

  ~TestQuicTransport() override {
    // we need to call close in the derived class.
    connCallback_ = nullptr;
    closeImpl(
        std::make_pair(
            QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
            std::string("shutdown")),
        false);
  }

  QuicVersion getVersion() {
    auto& conn = getConnectionState();
    return conn.version.value_or(*conn.originalVersion);
  }

  void updateWriteLooper(bool thisIteration) {
    QuicTransportBase::updateWriteLooper(thisIteration);
  }

  void pacedWrite(bool fromTimer) {
    pacedWriteDataToSocket(fromTimer);
  }

  bool isPacingScheduled() {
    return writeLooper_->isScheduled();
  }

  void onReadData(
      const folly::SocketAddress& /*peer*/,
      NetworkData&& /*networkData*/) noexcept override {}

  void writeData() override {
    if (closed) {
      return;
    }
    writeQuicDataToSocket(
        *socket_,
        *conn_,
        *conn_->clientConnectionId,
        *conn_->serverConnectionId,
        *aead,
        *headerCipher,
        getVersion(),
        (isConnectionPaced(*conn_)
             ? conn_->congestionController->getPacingRate(Clock::now())
             : conn_->transportSettings.writeConnectionDataPacketsLimit));
  }

  void closeTransport() override {
    closed = true;
  }

  bool hasWriteCipher() const override {
    return true;
  }

  std::shared_ptr<QuicTransportBase> sharedGuard() override {
    return shared_from_this();
  }

  void unbindConnection() {}

  QuicServerConnectionState& getConnectionState() {
    return *dynamic_cast<QuicServerConnectionState*>(conn_.get());
  }

  auto getAckTimeout() {
    return &ackTimeout_;
  }

  auto& getPathValidationTimeout() {
    return pathValidationTimeout_;
  }

  auto& lossTimeout() {
    return lossTimeout_;
  }

  CloseState closeState() {
    return closeState_;
  }

  folly::HHWheelTimer* getTimer() {
    return &getEventBase()->timer();
  }

  void drainImmediately() {
    drainTimeoutExpired();
  }

  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
  bool closed{false};
};

/**
 * A DeliveryCallback that closes your transport when it's canceled, or when
 * the targetOffset is delivered. Booyah!
 */
class TransportClosingDeliveryCallback : public QuicSocket::DeliveryCallback {
 public:
  explicit TransportClosingDeliveryCallback(
      TestQuicTransport* transport,
      uint64_t targetOffset)
      : transport_(transport), targetOffset_(targetOffset) {}

  void onDeliveryAck(StreamId, uint64_t offset, std::chrono::microseconds)
      override {
    if (offset >= targetOffset_) {
      transport_->close(folly::none);
    }
  }

  void onCanceled(StreamId, uint64_t) override {
    transport_->close(folly::none);
  }

 private:
  TestQuicTransport* transport_{nullptr};
  uint64_t targetOffset_;
};

class QuicTransportTest : public Test {
 public:
  ~QuicTransportTest() override = default;

  void SetUp() override {
    std::unique_ptr<MockAsyncUDPSocket> sock =
        std::make_unique<MockAsyncUDPSocket>(&evb_);
    socket_ = sock.get();
    transport_.reset(
        new TestQuicTransport(&evb_, std::move(sock), connCallback_));
    // Set the write handshake state to tell the client that the handshake has
    // a cipher.
    auto aead = std::make_unique<MockAead>();
    aead_ = aead.get();
    EXPECT_CALL(*aead_, _encrypt(_, _, _))
        .WillRepeatedly(
            Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
    EXPECT_CALL(*aead_, _decrypt(_, _, _))
        .WillRepeatedly(
            Invoke([&](auto& buf, auto, auto) { return buf->clone(); }));
    headerCipher_ = test::createNoOpHeaderCipher();
    transport_->getConnectionState().oneRttWriteCipher = std::move(aead);
    transport_->getConnectionState()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    transport_->getConnectionState()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    transport_->getConnectionState()
        .flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    transport_->getConnectionState().flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    transport_->getConnectionState()
        .streamManager->setMaxLocalBidirectionalStreams(
            kDefaultMaxStreamsBidirectional);
    transport_->getConnectionState()
        .streamManager->setMaxLocalUnidirectionalStreams(
            kDefaultMaxStreamsUnidirectional);
  }

  void loopForWrites() {
    // loop once to allow writes to take effect.
    evb_.loopOnce(EVLOOP_NONBLOCK);
  }

 protected:
  folly::EventBase evb_;
  MockAsyncUDPSocket* socket_;
  MockConnectionCallback connCallback_;
  MockWriteCallback writeCallback_;
  MockAead* aead_;
  std::unique_ptr<PacketNumberCipher> headerCipher_;
  std::shared_ptr<TestQuicTransport> transport_;
};

size_t bufLength(
    const SocketAddress&,
    const std::unique_ptr<folly::IOBuf>& buf) {
  return buf->computeChainDataLength();
}

void dropPackets(QuicServerConnectionState& conn) {
  for (const auto& packet : conn.outstandingPackets) {
    for (const auto& frame : packet.packet.frames) {
      const WriteStreamFrame* streamFrame =
          boost::get<WriteStreamFrame>(&frame);
      if (!streamFrame) {
        continue;
      }
      auto stream = conn.streamManager->findStream(streamFrame->streamId);
      ASSERT_TRUE(stream);
      auto itr = std::find_if(
          stream->retransmissionBuffer.begin(),
          stream->retransmissionBuffer.end(),
          [&streamFrame](const auto& buffer) {
            return streamFrame->offset == buffer.offset;
          });
      EXPECT_TRUE(itr != stream->retransmissionBuffer.end());
      stream->lossBuffer.insert(
          std::upper_bound(
              stream->lossBuffer.begin(),
              stream->lossBuffer.end(),
              itr->offset,
              [](const auto& offset, const auto& buffer) {
                return offset < buffer.offset;
              }),
          std::move(*itr));
      stream->retransmissionBuffer.erase(itr);
      if (std::find(
              conn.streamManager->lossStreams().begin(),
              conn.streamManager->lossStreams().end(),
              streamFrame->streamId) ==
          conn.streamManager->lossStreams().end()) {
        conn.streamManager->addLoss(streamFrame->streamId);
      }
    }
  }
  conn.outstandingPackets.clear();
}

// Helper function to verify the data of buffer is written to outstanding
// packets
void verifyCorrectness(
    const QuicServerConnectionState& conn,
    size_t originalWriteOffset,
    StreamId id,
    const folly::IOBuf& expected,
    bool finExpected = false,
    bool writeAll = true) {
  uint64_t endOffset = 0;
  size_t totalLen = 0;
  bool finSet = false;
  std::vector<uint64_t> offsets;
  for (const auto& packet : conn.outstandingPackets) {
    for (const auto& streamFrame :
         all_frames<WriteStreamFrame>(packet.packet.frames)) {
      if (streamFrame.streamId != id) {
        continue;
      }
      offsets.push_back(streamFrame.offset);
      endOffset = std::max(endOffset, streamFrame.offset + streamFrame.len);
      totalLen += streamFrame.len;
      finSet |= streamFrame.fin;
    }
  }
  auto stream = conn.streamManager->findStream(id);
  ASSERT_TRUE(stream);
  if (writeAll) {
    EXPECT_TRUE(stream->writeBuffer.empty());
  }
  EXPECT_EQ(stream->currentWriteOffset, endOffset + (finSet ? 1 : 0));
  EXPECT_EQ(
      stream->currentWriteOffset,
      originalWriteOffset + totalLen + (finSet ? 1 : 0));
  EXPECT_EQ(totalLen, expected.computeChainDataLength());
  EXPECT_EQ(finExpected, finSet);
  // Verify retransmissionBuffer:
  EXPECT_FALSE(stream->retransmissionBuffer.empty());
  IOBufQueue retxBufCombined;
  for (auto& retxBuf : stream->retransmissionBuffer) {
    retxBufCombined.append(retxBuf.data.front()->clone());
  }
  EXPECT_TRUE(IOBufEqualTo()(expected, *retxBufCombined.move()));
  EXPECT_EQ(finExpected, stream->retransmissionBuffer.back().eof);
  std::vector<uint64_t> retxBufOffsets;
  for (const auto& b : stream->retransmissionBuffer) {
    retxBufOffsets.push_back(b.offset);
  }
  EXPECT_EQ(offsets, retxBufOffsets);
}

TEST_F(QuicTransportTest, WriteDataWithProbing) {
  auto& conn = transport_->getConnectionState();
  // Replace with MockConnectionCallback:
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(kDefaultUDPSendPacketLen * 2);
  conn.pendingEvents.numProbePackets = 1;
  // Probing won't ask about getWritableBytes. Then regular write may ask
  // multiple times:
  int getWritableBytesCounter = 0;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        getWritableBytesCounter++;
        return kDefaultUDPSendPacketLen;
      }));
  // Probing will invoke onPacketSent once. Then regular write may invoke
  // multiple times:
  int onPacketSentCounter = 0;
  EXPECT_CALL(*rawCongestionController, onPacketSent(_))
      .WillRepeatedly(
          Invoke([&](const auto& /* packet */) { onPacketSentCounter++; }));
  // Probing will send out one. Then regular write may send out multiple ones:
  int socketWriteCounter = 0;
  EXPECT_CALL(*socket_, write(_, _))
      .WillRepeatedly(Invoke([&](const SocketAddress&,
                                 const std::unique_ptr<folly::IOBuf>& iobuf) {
        socketWriteCounter++;
        return iobuf->computeChainDataLength();
      }));
  transport_->writeChain(streamId, buf->clone(), true, false);
  loopForWrites();
  // Pending numProbePackets is cleared:
  EXPECT_EQ(0, conn.pendingEvents.numProbePackets);
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, NotAppLimitedWithLoss) {
  auto& conn = transport_->getConnectionState();
  // Replace with MockConnectionCallback:
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  auto stream = transport_->createBidirectionalStream().value();
  auto lossStream = transport_->createBidirectionalStream().value();
  conn.streamManager->addLoss(lossStream);
  conn.streamManager->getStream(lossStream)
      ->lossBuffer.emplace_back(
          IOBuf::copyBuffer("Mountains may depart"), 0, false);
  transport_->writeChain(
      stream,
      IOBuf::copyBuffer("An elephant sitting still"),
      false,
      false,
      nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(0);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, NotAppLimitedWithNoWritableBytes) {
  auto& conn = transport_->getConnectionState();
  // Replace with MockConnectionCallback:
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        if (conn.outstandingPackets.empty()) {
          return 5000;
        }
        return 0;
      }));

  auto stream = transport_->createBidirectionalStream().value();
  transport_->writeChain(
      stream,
      IOBuf::copyBuffer("An elephant sitting still"),
      false,
      false,
      nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(0);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, NotAppLimitedWithLargeBuffer) {
  auto& conn = transport_->getConnectionState();
  // Replace with MockConnectionCallback:
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100 * 2000);
  transport_->writeChain(stream, buf->clone(), false, false, nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(0);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, AppLimited) {
  auto& conn = transport_->getConnectionState();
  // Replace with MockConnectionCallback:
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(5000));

  auto stream = transport_->createBidirectionalStream().value();
  transport_->writeChain(
      stream,
      IOBuf::copyBuffer("An elephant sitting still"),
      false,
      false,
      nullptr);
  EXPECT_CALL(*rawCongestionController, setAppLimited()).Times(1);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, WriteSmall) {
  // Testing writing a small buffer that could be fit in a single packet
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);

  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);

  verifyCorrectness(conn, 0, stream, *buf);
  EXPECT_FALSE(shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteLarge) {
  // Testing writing a large buffer that would span multiple packets
  constexpr int NumFullPackets = 3;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf =
      buildRandomInputData(NumFullPackets * kDefaultUDPSendPacketLen + 20);
  folly::IOBuf passedIn;
  EXPECT_CALL(*socket_, write(_, _))
      .Times(NumFullPackets + 1)
      .WillRepeatedly(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(NumFullPackets + 1, conn.outstandingPackets.size());
  verifyCorrectness(conn, 0, stream, *buf);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _))
      .Times(NumFullPackets + 1)
      .WillRepeatedly(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(NumFullPackets + 1, conn.outstandingPackets.size());
  verifyCorrectness(conn, 0, stream, *buf);
  EXPECT_FALSE(shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteMultipleTimes) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  size_t originalWriteOffset =
      conn.streamManager->findStream(stream)->currentWriteOffset;
  verifyCorrectness(conn, 0, stream, *buf);

  conn.outstandingPackets.clear();
  conn.streamManager->findStream(stream)->retransmissionBuffer.clear();
  buf = buildRandomInputData(50);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();
  verifyCorrectness(conn, originalWriteOffset, stream, *buf);
  EXPECT_FALSE(shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteMultipleStreams) {
  // Testing writing to multiple streams
  auto s1 = transport_->createBidirectionalStream().value();
  auto s2 = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(s1, buf->clone(), false, false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, s1, *buf);

  auto buf2 = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(s2, buf2->clone(), false, false);
  loopForWrites();
  verifyCorrectness(conn, 0, s2, *buf2);

  dropPackets(conn);

  // Should retransmit lost streams in a single packet
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  verifyCorrectness(conn, 0, s1, *buf);
  verifyCorrectness(conn, 0, s2, *buf2);
}

TEST_F(QuicTransportTest, WriteFlowControl) {
  auto& conn = transport_->getConnectionState();
  auto streamId = transport_->createBidirectionalStream().value();
  auto stream = conn.streamManager->getStream(streamId);
  stream->flowControlState.peerAdvertisedMaxOffset = 100;
  stream->currentWriteOffset = 100;
  stream->conn.flowControlState.sumCurWriteOffset = 100;
  stream->conn.flowControlState.peerAdvertisedMaxOffset = 220;

  auto buf = buildRandomInputData(150);
  folly::IOBuf passedIn;
  // Write blocked frame
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(streamId, buf->clone(), false, false);

  loopForWrites();
  EXPECT_EQ(conn.outstandingPackets.size(), 1);
  auto& packet =
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  bool blockedFound = false;
  for (auto& blocked : all_frames<StreamDataBlockedFrame>(packet.frames)) {
    EXPECT_EQ(blocked.streamId, streamId);
    blockedFound = true;
  }
  EXPECT_TRUE(blockedFound);
  conn.outstandingPackets.clear();

  // Stream flow control
  auto buf1 = buf->clone();
  buf1->trimEnd(50);
  stream->flowControlState.peerAdvertisedMaxOffset = 200;
  conn.streamManager->updateWritableStreams(*stream);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  verifyCorrectness(conn, 100, streamId, *buf1, false, false);

  // Connection flow controled
  stream->flowControlState.peerAdvertisedMaxOffset = 300;
  conn.streamManager->updateWritableStreams(*stream);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  auto buf2 = buf->clone();
  buf2->trimEnd(30);
  verifyCorrectness(conn, 100, streamId, *buf2, false, false);

  // Flow control lifted
  stream->conn.flowControlState.peerAdvertisedMaxOffset = 300;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  verifyCorrectness(conn, 100, streamId, *buf, false, false);
}

TEST_F(QuicTransportTest, WriteErrorEagain) {
  // Test network error
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(SetErrnoAndReturn(EAGAIN, -1));
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();
}

TEST_F(QuicTransportTest, WriteErrorBad) {
  // Test network error
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(SetErrnoAndReturn(EBADF, -1));
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();
  EXPECT_TRUE(transport_->closed);
}

TEST_F(QuicTransportTest, WriteInvalid) {
  // Test writing to invalid stream
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  auto res = transport_->writeChain(stream + 2, buf->clone(), false, false);
  loopForWrites();
  EXPECT_EQ(LocalErrorCode::STREAM_NOT_EXISTS, res.error());
}

TEST_F(QuicTransportTest, WriteFin) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), true, false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf, true);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  verifyCorrectness(conn, 0, stream, *buf, true);
  EXPECT_FALSE(shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteOnlyFin) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, nullptr, true, false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf, true);

  // Test retransmission
  dropPackets(conn);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  verifyCorrectness(conn, 0, stream, *buf, true);
  EXPECT_FALSE(shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteDataWithRetransmission) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  verifyCorrectness(conn, 0, stream, *buf);

  dropPackets(conn);
  auto buf2 = buildRandomInputData(50);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf2->clone(), false, false);
  loopForWrites();
  // The first packet was lost. We should expect this packet contains both
  // lost data and new data
  buf->appendChain(std::move(buf2));
  verifyCorrectness(conn, 0, stream, *buf);
  EXPECT_FALSE(shouldWriteData(conn));
}

TEST_F(QuicTransportTest, WriteImmediateAcks) {
  auto& conn = transport_->getConnectionState();
  PacketNum start = 10;
  PacketNum end = 15;
  conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
  addAckStatesWithCurrentTimestamps(conn.ackStates.appDataAckState, start, end);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(conn.outstandingPackets.size(), 1);
  auto& packet =
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool ackFound = false;
  for (auto& ackFrame : all_frames<WriteAckFrame>(packet.frames)) {
    EXPECT_EQ(ackFrame.ackBlocks.size(), 1);
    EXPECT_EQ(start, ackFrame.ackBlocks.front().start);
    EXPECT_EQ(end, ackFrame.ackBlocks.front().end);
    ackFound = true;
  }
  EXPECT_TRUE(ackFound);

  EXPECT_EQ(conn.ackStates.appDataAckState.largestAckScheduled, end);
  EXPECT_FALSE(conn.ackStates.appDataAckState.needsToSendAckImmediately);
  EXPECT_EQ(0, conn.ackStates.appDataAckState.numNonRxPacketsRecvd);
  EXPECT_FALSE(shouldWriteData(conn));
}

TEST_F(QuicTransportTest, NotWriteAcksIfNoData) {
  auto& conn = transport_->getConnectionState();

  addAckStatesWithCurrentTimestamps(conn.ackStates.appDataAckState, 0, 100);
  conn.ackStates.appDataAckState.needsToSendAckImmediately = false;
  conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
  // Should not write ack blocks if there is only ack to write
  EXPECT_EQ(
      0,
      writeQuicDataToSocket(
          *socket_,
          conn,
          *conn.clientConnectionId,
          *conn.serverConnectionId,
          *aead_,
          *headerCipher_,
          transport_->getVersion(),
          conn.transportSettings.writeConnectionDataPacketsLimit));
}

TEST_F(QuicTransportTest, WritePendingAckIfHavingData) {
  auto& conn = transport_->getConnectionState();
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  PacketNum start = 10;
  PacketNum end = 15;
  addAckStatesWithCurrentTimestamps(conn.ackStates.appDataAckState, start, end);
  conn.ackStates.appDataAckState.needsToSendAckImmediately = false;
  conn.ackStates.appDataAckState.numNonRxPacketsRecvd = 3;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  // We should write acks if there is data pending
  transport_->writeChain(streamId, buf->clone(), true, false);
  loopForWrites();
  EXPECT_EQ(conn.outstandingPackets.size(), 1);
  auto& packet =
      getFirstOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  EXPECT_GE(packet.frames.size(), 2);

  bool ackFound = false;
  for (auto& ackFrame : all_frames<WriteAckFrame>(packet.frames)) {
    EXPECT_EQ(ackFrame.ackBlocks.size(), 1);
    EXPECT_EQ(ackFrame.ackBlocks.front().start, start);
    EXPECT_EQ(ackFrame.ackBlocks.front().end, end);
    ackFound = true;
  }
  EXPECT_TRUE(ackFound);
  EXPECT_EQ(conn.ackStates.appDataAckState.largestAckScheduled, end);

  // Verify ack state after writing
  auto pnSpace = folly::variant_match(
      packet.header, [](const auto& h) { return h.getPacketNumberSpace(); });
  auto ackState = getAckState(conn, pnSpace);
  EXPECT_EQ(ackState.largestAckScheduled, end);
  EXPECT_FALSE(ackState.needsToSendAckImmediately);
  EXPECT_EQ(0, ackState.numNonRxPacketsRecvd);
}

TEST_F(QuicTransportTest, RstStream) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_EQ(1, transport_->getConnectionState().outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_GE(packet.frames.size(), 1);
  bool rstFound = false;
  for (auto& frame : all_frames<RstStreamFrame>(packet.frames)) {
    EXPECT_EQ(streamId, frame.streamId);
    EXPECT_EQ(0, frame.offset);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, frame.errorCode);
    rstFound = true;
  }
  EXPECT_TRUE(rstFound);

  auto stream =
      transport_->getConnectionState().streamManager->findStream(streamId);
  ASSERT_TRUE(stream);
  EXPECT_TRUE(isState<StreamSendStates::ResetSent>(stream->send));
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->writeBuffer.empty());
  EXPECT_FALSE(stream->writable());
  EXPECT_TRUE(stream->writeBuffer.empty());
  EXPECT_FALSE(transport_->getConnectionState().streamManager->writableContains(
      stream->id));
}

TEST_F(QuicTransportTest, StopSending) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->stopSending(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_EQ(1, transport_->getConnectionState().outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_EQ(16, packet.frames.size());
  bool foundStopSending = false;
  for (auto& simpleFrame : all_frames<QuicSimpleFrame>(packet.frames)) {
    folly::variant_match(
        simpleFrame,
        [&](const StopSendingFrame& frame) {
          EXPECT_EQ(streamId, frame.streamId);
          EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, frame.errorCode);
          foundStopSending = true;
        },
        [&](auto&) {});
  }
  EXPECT_TRUE(foundStopSending);
}

TEST_F(QuicTransportTest, SendPathChallenge) {
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  transport_->updateWriteLooper(true);

  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(conn.outstandingPathValidation);
  EXPECT_FALSE(transport_->getPathValidationTimeout().isScheduled());
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(conn.outstandingPathValidation);
  EXPECT_EQ(conn.outstandingPathValidation, pathChallenge);
  EXPECT_TRUE(transport_->getPathValidationTimeout().isScheduled());

  EXPECT_EQ(1, transport_->getConnectionState().outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  bool foundPathChallenge = false;
  for (auto& simpleFrame : all_frames<QuicSimpleFrame>(packet.frames)) {
    folly::variant_match(
        simpleFrame,
        [&](const PathChallengeFrame& frame) {
          EXPECT_EQ(frame, pathChallenge);
          foundPathChallenge = true;
        },
        [&](auto&) {});
  }
  EXPECT_TRUE(foundPathChallenge);
}

TEST_F(QuicTransportTest, PathValidationTimeoutExpired) {
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  transport_->updateWriteLooper(true);

  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(conn.outstandingPathValidation);
  EXPECT_FALSE(transport_->getPathValidationTimeout().isScheduled());
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(conn.outstandingPathValidation);
  EXPECT_EQ(conn.outstandingPathValidation, pathChallenge);
  EXPECT_TRUE(transport_->getPathValidationTimeout().isScheduled());

  EXPECT_EQ(1, transport_->getConnectionState().outstandingPackets.size());

  transport_->getPathValidationTimeout().cancelTimeout();
  transport_->getPathValidationTimeout().timeoutExpired();
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(conn.outstandingPathValidation);
  EXPECT_EQ(transport_->closeState(), CloseState::CLOSED);
  EXPECT_TRUE(conn.localConnectionError);
  EXPECT_EQ(
      conn.localConnectionError->first,
      QuicErrorCode(TransportErrorCode::INVALID_MIGRATION));
  EXPECT_EQ(conn.localConnectionError->second, "Path validation timed out");
}

TEST_F(QuicTransportTest, SendPathValidationWhileThereIsOutstandingOne) {
  auto& conn = transport_->getConnectionState();
  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_TRUE(conn.outstandingPathValidation);
  EXPECT_EQ(conn.outstandingPathValidation, pathChallenge);
  EXPECT_TRUE(transport_->getPathValidationTimeout().isScheduled());

  EXPECT_EQ(1, transport_->getConnectionState().outstandingPackets.size());

  PathChallengeFrame pathChallenge2(456);
  transport_->getPathValidationTimeout().cancelTimeout();
  conn.pendingEvents.schedulePathValidationTimeout = false;
  conn.outstandingPathValidation = folly::none;
  conn.pendingEvents.pathChallenge = pathChallenge2;
  EXPECT_EQ(conn.pendingEvents.pathChallenge, pathChallenge2);
  EXPECT_FALSE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_FALSE(conn.outstandingPathValidation);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  EXPECT_TRUE(conn.pendingEvents.schedulePathValidationTimeout);
  EXPECT_EQ(conn.outstandingPathValidation, pathChallenge2);
  EXPECT_TRUE(transport_->getPathValidationTimeout().isScheduled());

  EXPECT_EQ(2, transport_->getConnectionState().outstandingPackets.size());
}

TEST_F(QuicTransportTest, ClonePathChallenge) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandingHandshakePacketsCount = 0;
  conn.outstandingPureAckPacketsCount = 0;
  conn.outstandingPackets.clear();
  conn.lossState.initialLossTime.clear();
  conn.lossState.handshakeLossTime.clear();
  conn.lossState.appDataLossTime.clear();

  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(conn.outstandingPackets.size(), 1);
  auto numPathChallengePackets = std::count_if(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      [&](auto& p) {
        return std::find_if(
                   p.packet.frames.begin(),
                   p.packet.frames.end(),
                   [&](auto& f) {
                     return folly::variant_match(
                         f,
                         [&](QuicSimpleFrame& s) {
                           return folly::variant_match(
                               s,
                               [&](PathChallengeFrame&) { return true; },
                               [&](auto&) { return false; });
                         },
                         [&](auto&) { return false; });
                   }) != p.packet.frames.end();
      });
  EXPECT_EQ(numPathChallengePackets, 1);

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  // On PTO, endpoint sends 2 probing packets, thus 1+2=3
  EXPECT_EQ(conn.outstandingPackets.size(), 3);
  numPathChallengePackets = std::count_if(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      [&](auto& p) {
        return std::find_if(
                   p.packet.frames.begin(),
                   p.packet.frames.end(),
                   [&](auto& f) {
                     return folly::variant_match(
                         f,
                         [&](QuicSimpleFrame& s) {
                           return folly::variant_match(
                               s,
                               [&](PathChallengeFrame&) { return true; },
                               [&](auto&) { return false; });
                         },
                         [&](auto&) { return false; });
                   }) != p.packet.frames.end();
      });
  EXPECT_EQ(numPathChallengePackets, 3);
}

TEST_F(QuicTransportTest, OnlyClonePathValidationIfOutstanding) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandingHandshakePacketsCount = 0;
  conn.outstandingPureAckPacketsCount = 0;
  conn.outstandingPackets.clear();
  conn.lossState.initialLossTime.clear();
  conn.lossState.handshakeLossTime.clear();
  conn.lossState.appDataLossTime.clear();

  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  transport_->updateWriteLooper(true);
  loopForWrites();

  auto numPathChallengePackets = std::count_if(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      [&](auto& p) {
        return std::find_if(
                   p.packet.frames.begin(),
                   p.packet.frames.end(),
                   [&](auto& f) {
                     return folly::variant_match(
                         f,
                         [&](QuicSimpleFrame& s) {
                           return folly::variant_match(
                               s,
                               [&](PathChallengeFrame&) { return true; },
                               [&](auto&) { return false; });
                         },
                         [&](auto&) { return false; });
                   }) != p.packet.frames.end();
      });
  EXPECT_EQ(numPathChallengePackets, 1);

  // Reset outstandingPathValidation
  // This could happen when an endpoint migrates to an unvalidated address, and
  // then migrates back to a validated address before timer expires
  conn.outstandingPathValidation = folly::none;

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  numPathChallengePackets = std::count_if(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      [&](auto& p) {
        return std::find_if(
                   p.packet.frames.begin(),
                   p.packet.frames.end(),
                   [&](auto& f) {
                     return folly::variant_match(
                         f,
                         [&](QuicSimpleFrame& s) {
                           return folly::variant_match(
                               s,
                               [&](PathChallengeFrame&) { return true; },
                               [&](auto&) { return false; });
                         },
                         [&](auto&) { return false; });
                   }) != p.packet.frames.end();
      });
  EXPECT_EQ(numPathChallengePackets, 1);
}

TEST_F(QuicTransportTest, ResendPathChallengeOnLoss) {
  auto& conn = transport_->getConnectionState();

  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;

  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  markPacketLoss(conn, packet, false, 2);
  EXPECT_EQ(*conn.pendingEvents.pathChallenge, pathChallenge);
}

TEST_F(QuicTransportTest, DoNotResendLostPathChallengeIfNotOutstanding) {
  auto& conn = transport_->getConnectionState();

  PathChallengeFrame pathChallenge(123);
  conn.pendingEvents.pathChallenge = pathChallenge;
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;

  // Fire path validation timer
  transport_->getPathValidationTimeout().cancelTimeout();
  transport_->getPathValidationTimeout().timeoutExpired();

  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
  markPacketLoss(conn, packet, false, 2);
  EXPECT_FALSE(conn.pendingEvents.pathChallenge);
}

TEST_F(QuicTransportTest, SendPathResponse) {
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  PathResponseFrame pathResponse(123);
  sendSimpleFrame(conn, pathResponse);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);

  EXPECT_EQ(1, conn.outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  bool foundPathResponse = false;
  for (auto& simpleFrame : all_frames<QuicSimpleFrame>(packet.frames)) {
    folly::variant_match(
        simpleFrame,
        [&](const PathResponseFrame& frame) {
          EXPECT_EQ(frame, pathResponse);
          foundPathResponse = true;
        },
        [&](auto&) {});
  }
  EXPECT_TRUE(foundPathResponse);
}

TEST_F(QuicTransportTest, CloneAfterRecvReset) {
  auto& conn = transport_->getConnectionState();
  auto streamId = transport_->createBidirectionalStream().value();
  transport_->writeChain(streamId, IOBuf::create(0), true, false);
  loopForWrites();
  EXPECT_EQ(1, conn.outstandingPackets.size());
  auto stream = conn.streamManager->getStream(streamId);
  EXPECT_EQ(1, stream->retransmissionBuffer.size());
  EXPECT_EQ(0, stream->retransmissionBuffer.back().offset);
  EXPECT_EQ(0, stream->retransmissionBuffer.back().data.chainLength());
  EXPECT_TRUE(stream->retransmissionBuffer.back().eof);
  EXPECT_TRUE(stream->lossBuffer.empty());
  EXPECT_EQ(0, stream->writeBuffer.chainLength());
  EXPECT_EQ(1, stream->currentWriteOffset);
  EXPECT_EQ(0, *stream->finalWriteOffset);

  RstStreamFrame rstFrame(streamId, GenericApplicationErrorCode::UNKNOWN, 0);
  invokeStreamReceiveStateMachine(conn, *stream, std::move(rstFrame));

  // This will clone twice. :/ Maybe we should change this to clone only once in
  // the future, thus the EXPECT were written with LT and LE. But it will clone
  // for sure and we shouldn't crash.
  transport_->lossTimeout().timeoutExpired();
  EXPECT_LT(1, conn.outstandingPackets.size());
  size_t cloneCounter = std::count_if(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      [](const auto& packet) { return packet.associatedEvent.hasValue(); });
  EXPECT_LE(1, cloneCounter);
}

TEST_F(QuicTransportTest, ClonePathResponse) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandingHandshakePacketsCount = 0;
  conn.outstandingPureAckPacketsCount = 0;
  conn.outstandingPackets.clear();
  conn.lossState.initialLossTime.clear();
  conn.lossState.handshakeLossTime.clear();
  conn.lossState.appDataLossTime.clear();

  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  PathResponseFrame pathResponse(123);
  sendSimpleFrame(conn, pathResponse);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);

  auto numPathResponsePackets = std::count_if(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      [&](auto& p) {
        return std::find_if(
                   p.packet.frames.begin(),
                   p.packet.frames.end(),
                   [&](auto& f) {
                     return folly::variant_match(
                         f,
                         [&](QuicSimpleFrame& s) {
                           return folly::variant_match(
                               s,
                               [&](PathResponseFrame&) { return true; },
                               [&](auto&) { return false; });
                         },
                         [&](auto&) { return false; });
                   }) != p.packet.frames.end();
      });
  EXPECT_EQ(numPathResponsePackets, 1);

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  numPathResponsePackets = std::count_if(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      [&](auto& p) {
        return std::find_if(
                   p.packet.frames.begin(),
                   p.packet.frames.end(),
                   [&](auto& f) {
                     return folly::variant_match(
                         f,
                         [&](QuicSimpleFrame& s) {
                           return folly::variant_match(
                               s,
                               [&](PathResponseFrame&) { return true; },
                               [&](auto&) { return false; });
                         },
                         [&](auto&) { return false; });
                   }) != p.packet.frames.end();
      });
  EXPECT_EQ(numPathResponsePackets, 3);
}

TEST_F(QuicTransportTest, ResendPathResponseOnLoss) {
  auto& conn = transport_->getConnectionState();

  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  PathResponseFrame pathResponse(123);
  sendSimpleFrame(conn, pathResponse);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  transport_->updateWriteLooper(true);
  loopForWrites();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);

  EXPECT_EQ(1, conn.outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;

  markPacketLoss(conn, packet, false, 2);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  EXPECT_TRUE(folly::variant_match(
      conn.pendingEvents.frames.front(),
      [&](PathResponseFrame& f) { return f == pathResponse; },
      [&](auto&) { return false; }));
}

TEST_F(QuicTransportTest, SendNewConnectionIdFrame) {
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  NewConnectionIdFrame newConnId(
      1, ConnectionId({2, 4, 2, 3}), StatelessResetToken());
  sendSimpleFrame(conn, newConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  EXPECT_EQ(1, transport_->getConnectionState().outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  bool foundNewConnectionId = false;
  for (auto& simpleFrame : all_frames<QuicSimpleFrame>(packet.frames)) {
    folly::variant_match(
        simpleFrame,
        [&](const NewConnectionIdFrame& frame) {
          EXPECT_EQ(frame, newConnId);
          foundNewConnectionId = true;
        },
        [&](auto&) {});
  }
  EXPECT_TRUE(foundNewConnectionId);
}

TEST_F(QuicTransportTest, CloneNewConnectionIdFrame) {
  auto& conn = transport_->getConnectionState();
  // knock every handshake outstanding packets out
  conn.outstandingHandshakePacketsCount = 0;
  conn.outstandingPureAckPacketsCount = 0;
  conn.outstandingPackets.clear();
  conn.lossState.initialLossTime.clear();
  conn.lossState.handshakeLossTime.clear();
  conn.lossState.appDataLossTime.clear();

  NewConnectionIdFrame newConnId(
      1, ConnectionId({2, 4, 2, 3}), StatelessResetToken());
  sendSimpleFrame(conn, newConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(conn.outstandingPackets.size(), 1);
  auto numNewConnIdPackets = std::count_if(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      [&](auto& p) {
        return std::find_if(
                   p.packet.frames.begin(),
                   p.packet.frames.end(),
                   [&](auto& f) {
                     return folly::variant_match(
                         f,
                         [&](QuicSimpleFrame& s) {
                           return folly::variant_match(
                               s,
                               [&](NewConnectionIdFrame&) { return true; },
                               [&](auto&) { return false; });
                         },
                         [&](auto&) { return false; });
                   }) != p.packet.frames.end();
      });
  EXPECT_EQ(numNewConnIdPackets, 1);

  // Force a timeout with no data so that it clones the packet
  transport_->lossTimeout().timeoutExpired();
  // On PTO, endpoint sends 2 probing packets, thus 1+2=3
  EXPECT_EQ(conn.outstandingPackets.size(), 3);
  numNewConnIdPackets = std::count_if(
      conn.outstandingPackets.begin(),
      conn.outstandingPackets.end(),
      [&](auto& p) {
        return std::find_if(
                   p.packet.frames.begin(),
                   p.packet.frames.end(),
                   [&](auto& f) {
                     return folly::variant_match(
                         f,
                         [&](QuicSimpleFrame& s) {
                           return folly::variant_match(
                               s,
                               [&](NewConnectionIdFrame&) { return true; },
                               [&](auto&) { return false; });
                         },
                         [&](auto&) { return false; });
                   }) != p.packet.frames.end();
      });
  EXPECT_EQ(numNewConnIdPackets, 3);
}

TEST_F(QuicTransportTest, ResendNewConnectionIdOnLoss) {
  auto& conn = transport_->getConnectionState();

  NewConnectionIdFrame newConnId(
      1, ConnectionId({2, 4, 2, 3}), StatelessResetToken());
  sendSimpleFrame(conn, newConnId);
  transport_->updateWriteLooper(true);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;

  EXPECT_TRUE(conn.pendingEvents.frames.empty());
  markPacketLoss(conn, packet, false, 2);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  EXPECT_TRUE(folly::variant_match(
      conn.pendingEvents.frames.front(),
      [&](NewConnectionIdFrame& f) { return f == newConnId; },
      [&](auto&) { return false; }));
}

TEST_F(QuicTransportTest, NonWritableStreamAPI) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  auto& conn = transport_->getConnectionState();
  auto streamState = conn.streamManager->getStream(streamId);

  // write EOF
  transport_->writeChain(streamId, buf->clone(), true, false);
  loopForWrites();
  EXPECT_FALSE(streamState->writable());

  // add a streamFlowControl event
  conn.streamManager->queueFlowControlUpdated(streamState->id);
  // check that no flow control update or onConnectionWriteReady callback gets
  // called on the stream after this
  EXPECT_CALL(connCallback_, onFlowControlUpdate(streamState->id)).Times(0);
  EXPECT_CALL(writeCallback_, onStreamWriteReady(streamState->id, _)).Times(0);
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  // Check that write-side APIs return an error
  auto res = transport_->getStreamFlowControl(streamId);
  EXPECT_EQ(LocalErrorCode::STREAM_CLOSED, res.error());
  auto res1 = transport_->setStreamFlowControlWindow(streamId, 0);
  EXPECT_EQ(LocalErrorCode::STREAM_CLOSED, res1.error());
  auto res2 = transport_->notifyPendingWriteOnStream(streamId, &writeCallback_);
  EXPECT_EQ(LocalErrorCode::STREAM_CLOSED, res2.error());
}

TEST_F(QuicTransportTest, RstWrittenStream) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  transport_->writeChain(streamId, buf->clone(), false, false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->findStream(streamId);
  ASSERT_TRUE(stream);
  auto currentWriteOffset = stream->currentWriteOffset;

  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  // 2 packets are outstanding: one for Stream frame one for RstStream frame:
  EXPECT_EQ(2, transport_->getConnectionState().outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : all_frames<RstStreamFrame>(packet.frames)) {
    EXPECT_EQ(streamId, frame.streamId);
    EXPECT_EQ(currentWriteOffset, frame.offset);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, frame.errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);

  EXPECT_TRUE(isState<StreamSendStates::ResetSent>(stream->send));
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->writeBuffer.empty());
  EXPECT_FALSE(stream->writable());
  EXPECT_FALSE(transport_->getConnectionState().streamManager->writableContains(
      stream->id));
}

TEST_F(QuicTransportTest, RstStreamUDPWriteFailNonFatal) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(SetErrnoAndReturn(EAGAIN, -1));
  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();

  EXPECT_EQ(1, transport_->getConnectionState().outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(
          transport_->getConnectionState(), PacketNumberSpace::AppData)
          ->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : all_frames<RstStreamFrame>(packet.frames)) {
    EXPECT_EQ(streamId, frame.streamId);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, frame.errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);

  auto stream =
      transport_->getConnectionState().streamManager->findStream(streamId);
  ASSERT_TRUE(stream);

  // Though fail to write RstStream frame to the socket, we still should mark
  // this steam unwriable and drop current writeBuffer and
  // retransmissionBuffer:
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->writeBuffer.empty());
  EXPECT_FALSE(stream->writable());
}

TEST_F(QuicTransportTest, RstStreamUDPWriteFailFatal) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _))
      .WillRepeatedly(SetErrnoAndReturn(EBADF, -1));
  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();
  EXPECT_TRUE(transport_->getConnectionState().outstandingPackets.empty());

  // Streams should be empty now since the connection will be closed.
  EXPECT_EQ(transport_->getConnectionState().streamManager->streamCount(), 0);
}

TEST_F(QuicTransportTest, WriteAfterSendRst) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  transport_->writeChain(streamId, buf->clone(), false, false);
  loopForWrites();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->findStream(streamId);
  ASSERT_TRUE(stream);
  auto currentWriteOffset = stream->currentWriteOffset;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN);
  loopForWrites();

  EXPECT_TRUE(isState<StreamSendStates::ResetSent>(stream->send));
  EXPECT_TRUE(stream->retransmissionBuffer.empty());
  EXPECT_TRUE(stream->writeBuffer.empty());
  EXPECT_FALSE(stream->writable());
  EXPECT_FALSE(transport_->getConnectionState().streamManager->writableContains(
      stream->id));

  // Write again:
  buf = buildRandomInputData(50);
  // This shall fail:
  auto res = transport_->writeChain(streamId, buf->clone(), false, false);
  loopForWrites();
  EXPECT_EQ(LocalErrorCode::STREAM_CLOSED, res.error());

  // only 2 packets are outstanding: one for Stream frame one for RstStream
  // frame. The 2nd writeChain won't write anything.
  EXPECT_EQ(2, conn.outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  EXPECT_GE(packet.frames.size(), 1);

  bool foundReset = false;
  for (auto& frame : all_frames<RstStreamFrame>(packet.frames)) {
    EXPECT_EQ(streamId, frame.streamId);
    EXPECT_EQ(currentWriteOffset, frame.offset);
    EXPECT_EQ(GenericApplicationErrorCode::UNKNOWN, frame.errorCode);
    foundReset = true;
  }
  EXPECT_TRUE(foundReset);

  // writeOffset isn't moved by the 2nd write:
  EXPECT_EQ(currentWriteOffset, stream->currentWriteOffset);
}

TEST_F(QuicTransportTest, DoubleReset) {
  auto streamId = transport_->createBidirectionalStream().value();
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  EXPECT_FALSE(
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
  loopForWrites();

  // Then reset again, which is a no-op:
  EXPECT_FALSE(
      transport_->resetStream(streamId, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
}

TEST_F(QuicTransportTest, WriteStreamDataSetLossAlarm) {
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(1);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();
  EXPECT_TRUE(transport_->isLossTimeoutScheduled());
}

TEST_F(QuicTransportTest, WriteAckNotSetLossAlarm) {
  auto& conn = transport_->getConnectionState();
  addAckStatesWithCurrentTimestamps(
      conn.ackStates.appDataAckState, 0 /* start */, 100 /* ind */);
  conn.ackStates.appDataAckState.needsToSendAckImmediately = true;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto res = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, res); // Write one packet out
  EXPECT_FALSE(transport_->isLossTimeoutScheduled()); // no alarm scheduled
}

TEST_F(QuicTransportTest, WriteWindowUpdate) {
  auto& conn = transport_->getConnectionState();
  conn.flowControlState.windowSize = 100;
  conn.flowControlState.advertisedMaxOffset = 0;
  conn.pendingEvents.connWindowUpdate = true;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  auto res = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, res); // Write one packet out
  EXPECT_EQ(1, conn.outstandingPackets.size());
  auto packet =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  EXPECT_GE(packet.frames.size(), 1);
  bool connWindowFound = false;
  for (auto& connWindowUpdate : all_frames<MaxDataFrame>(packet.frames)) {
    EXPECT_EQ(100, connWindowUpdate.maximumData);
    connWindowFound = true;
  }

  EXPECT_TRUE(connWindowFound);

  EXPECT_EQ(conn.flowControlState.advertisedMaxOffset, 100);
  conn.outstandingPackets.clear();

  auto stream = transport_->createBidirectionalStream().value();
  auto streamState = conn.streamManager->getStream(stream);
  streamState->flowControlState.windowSize = 100;
  streamState->flowControlState.advertisedMaxOffset = 0;
  MaxStreamDataFrame frame(stream, 100);
  conn.streamManager->queueWindowUpdate(stream);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  res = writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, res); // Write one packet out
  EXPECT_EQ(1, conn.outstandingPackets.size());
  auto packet1 =
      getLastOutstandingPacket(conn, PacketNumberSpace::AppData)->packet;
  const MaxStreamDataFrame* streamWindowUpdate =
      boost::get<MaxStreamDataFrame>(&packet1.frames.front());
  EXPECT_TRUE(streamWindowUpdate);
}

TEST_F(QuicTransportTest, FlowControlCallbacks) {
  auto stream = transport_->createBidirectionalStream().value();
  auto stream2 = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto streamState = conn.streamManager->getStream(stream);
  auto streamState2 = conn.streamManager->getStream(stream2);

  conn.streamManager->queueFlowControlUpdated(streamState->id);
  conn.streamManager->queueFlowControlUpdated(streamState2->id);
  EXPECT_CALL(connCallback_, onFlowControlUpdate(streamState->id));
  EXPECT_CALL(connCallback_, onFlowControlUpdate(streamState2->id));
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  EXPECT_FALSE(conn.streamManager->popFlowControlUpdated().hasValue());
}

TEST_F(QuicTransportTest, DeliveryCallbackClosesClosedTransport) {
  auto stream1 = transport_->createBidirectionalStream().value();
  auto buf1 = buildRandomInputData(20);
  TransportClosingDeliveryCallback dc(transport_.get(), 20);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->writeChain(stream1, buf1->clone(), true, false, &dc);
  loopForWrites();
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, DeliveryCallbackClosesTransportOnDelivered) {
  auto stream1 = transport_->createBidirectionalStream().value();
  auto buf1 = buildRandomInputData(20);
  TransportClosingDeliveryCallback dc(transport_.get(), 0);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream1, 0, &dc);
  transport_->writeChain(stream1, buf1->clone(), true, false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  conn.streamManager->addDeliverable(stream1);
  folly::SocketAddress addr;
  NetworkData emptyData;
  // This will invoke the DeliveryClalback::onDelivered
  transport_->onNetworkData(addr, std::move(emptyData));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksNothingDelivered) {
  MockDeliveryCallback mockedDeliveryCallback;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream, 1, &mockedDeliveryCallback);
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();

  folly::SocketAddress addr;
  NetworkData emptyData;
  transport_->onNetworkData(addr, std::move(emptyData));

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  transport_->writeChain(stream, buf2->clone(), true, false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  auto streamState = conn.streamManager->getStream(stream);
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  NetworkData emptyData2;
  EXPECT_CALL(mockedDeliveryCallback, onDeliveryAck(stream, 1, 100us)).Times(1);
  transport_->onNetworkData(addr, std::move(emptyData2));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksAllDelivered) {
  MockDeliveryCallback mockedDeliveryCallback;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(20);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream, 1, &mockedDeliveryCallback);
  transport_->writeChain(stream, buf->clone(), true, false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  // Faking a delivery:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->retransmissionBuffer.clear();

  folly::SocketAddress addr;
  NetworkData emptyData;
  EXPECT_CALL(mockedDeliveryCallback, onDeliveryAck(stream, 1, 100us)).Times(1);
  transport_->onNetworkData(addr, std::move(emptyData));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksPartialDelivered) {
  MockDeliveryCallback mockedDeliveryCallback1, mockedDeliveryCallback2;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream, 50, &mockedDeliveryCallback1);
  transport_->registerDeliveryCallback(stream, 150, &mockedDeliveryCallback2);
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  // Faking a delivery:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->retransmissionBuffer.clear();

  folly::SocketAddress addr;
  NetworkData emptyData;
  EXPECT_CALL(mockedDeliveryCallback1, onDeliveryAck(stream, 50, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData));

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  transport_->writeChain(stream, buf2->clone(), true, false);
  loopForWrites();
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  NetworkData emptyData2;
  EXPECT_CALL(mockedDeliveryCallback2, onDeliveryAck(stream, 150, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData2));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksRetxBuffer) {
  MockDeliveryCallback mockedDeliveryCallback1, mockedDeliveryCallback2;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream, 50, &mockedDeliveryCallback1);
  transport_->registerDeliveryCallback(stream, 150, &mockedDeliveryCallback2);
  transport_->writeChain(stream, buf->clone(), false, false);

  loopForWrites();
  auto& conn = transport_->getConnectionState();
  // Faking a delivery and retx:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->retransmissionBuffer.clear();
  streamState->retransmissionBuffer.emplace_back(
      folly::IOBuf::copyBuffer("But i'm not delivered yet"), 51, false);

  folly::SocketAddress addr;
  NetworkData emptyData;
  EXPECT_CALL(mockedDeliveryCallback1, onDeliveryAck(stream, 50, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData));

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  transport_->writeChain(stream, buf2->clone(), true, false);
  loopForWrites();
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  NetworkData emptyData2;
  EXPECT_CALL(mockedDeliveryCallback2, onDeliveryAck(stream, 150, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData2));
}

TEST_F(QuicTransportTest, InvokeDeliveryCallbacksLossAndRetxBuffer) {
  MockDeliveryCallback mockedDeliveryCallback1, mockedDeliveryCallback2,
      mockedDeliveryCallback3;
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(100);
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->registerDeliveryCallback(stream, 30, &mockedDeliveryCallback1);
  transport_->registerDeliveryCallback(stream, 50, &mockedDeliveryCallback2);
  transport_->registerDeliveryCallback(stream, 150, &mockedDeliveryCallback3);
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();

  auto& conn = transport_->getConnectionState();
  // Faking a delivery, retx and loss:
  conn.streamManager->addDeliverable(stream);
  conn.lossState.srtt = 100us;
  auto streamState = conn.streamManager->getStream(stream);
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  streamState->retransmissionBuffer.emplace_back(
      folly::IOBuf::copyBuffer("But i'm not delivered yet"), 51, false);
  streamState->lossBuffer.emplace_back(
      folly::IOBuf::copyBuffer("And I'm lost"), 31, false);

  folly::SocketAddress addr;
  NetworkData emptyData;
  EXPECT_CALL(mockedDeliveryCallback1, onDeliveryAck(stream, 30, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData));

  // Clear out the other delivery callbacks before tear down transport.
  // Otherwise, transport will be holding on to delivery callback pointers
  // that are already dead:
  auto buf2 = buildRandomInputData(100);
  transport_->writeChain(stream, buf2->clone(), true, false);
  loopForWrites();
  streamState->retransmissionBuffer.clear();
  streamState->lossBuffer.clear();
  conn.streamManager->addDeliverable(stream);
  NetworkData emptyData2;
  EXPECT_CALL(mockedDeliveryCallback2, onDeliveryAck(stream, 50, 100us))
      .Times(1);
  EXPECT_CALL(mockedDeliveryCallback3, onDeliveryAck(stream, 150, 100us))
      .Times(1);
  transport_->onNetworkData(addr, std::move(emptyData2));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnImmediate) {
  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));
  transport_->notifyPendingWriteOnConnection(&writeCallback_);
  evb_.loop();
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamImmediate) {
  auto stream = transport_->createBidirectionalStream().value();
  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream, _));
  transport_->notifyPendingWriteOnStream(stream, &writeCallback_);
  evb_.loop();

  StreamId nonExistentStream = 3;
  EXPECT_TRUE(
      transport_->notifyPendingWriteOnStream(nonExistentStream, &writeCallback_)
          .hasError());
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnAsync) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the conn flow control to have no bytes remaining.
  updateFlowControlOnWriteToStream(
      *stream, conn.flowControlState.peerAdvertisedMaxOffset);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);
  transport_->notifyPendingWriteOnConnection(&writeCallback_);
  evb_.loop();

  PacketNum num = 10;
  // Give the conn some headroom.
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnBufferFreeUpSpace) {
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable = 100;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->getStream(streamId);

  // Fill up the buffer to its limit
  updateFlowControlOnWriteToStream(*stream, 100);
  transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  // Write 10 bytes to the socket to free up space
  updateFlowControlOnWriteToSocket(*stream, 10);
  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnBufferUseTotalSpace) {
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable = 100;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->getStream(streamId);

  // Fill up the buffer to its limit
  updateFlowControlOnWriteToStream(*stream, 100);
  transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnBufferOveruseSpace) {
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable = 100;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();
  auto stream = conn.streamManager->getStream(streamId);

  // Fill up the buffer to its limit
  updateFlowControlOnWriteToStream(*stream, 1000);
  transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(
    QuicTransportTest,
    NotifyPendingWriteConnBufferGreaterThanConnFlowWindow) {
  auto& conn = transport_->getConnectionState();
  TransportSettings transportSettings;
  transportSettings.totalBufferSpaceAvailable =
      conn.flowControlState.peerAdvertisedMaxOffset + 1;
  transport_->setTransportSettings(transportSettings);

  auto streamId = transport_->createBidirectionalStream().value();
  auto stream = conn.streamManager->getStream(streamId);

  // Use up the entire flow control (but not the buffer space)
  updateFlowControlOnWriteToStream(
      *stream, conn.flowControlState.peerAdvertisedMaxOffset);
  transport_->notifyPendingWriteOnConnection(&writeCallback_);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);

  evb_.loop();

  // Give the conn some headroom, but don't free up any buffer space
  PacketNum num = 10;
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_));

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamAsyncConnBlocked) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the conn flow control to have no bytes remaining.
  updateFlowControlOnWriteToStream(
      *stream, conn.flowControlState.peerAdvertisedMaxOffset);

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _)).Times(0);
  transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  evb_.loop();

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _));

  PacketNum num = 10;
  // Give the conn some headroom.
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamAsyncStreamBlocked) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the stream flow control to have no bytes remaining.
  stream->currentWriteOffset = stream->flowControlState.peerAdvertisedMaxOffset;

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _)).Times(0);
  transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  evb_.loop();

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));

  PacketNum num = 10;
  handleStreamWindowUpdate(
      *stream, stream->flowControlState.peerAdvertisedMaxOffset + 1000, num);
  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _));
  EXPECT_CALL(connCallback_, onFlowControlUpdate(stream->id));

  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnTwice) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the conn flow control to have no bytes remaining.
  updateFlowControlOnWriteToStream(
      *stream, conn.flowControlState.peerAdvertisedMaxOffset);

  EXPECT_CALL(writeCallback_, onConnectionWriteReady(_)).Times(0);
  EXPECT_FALSE(
      transport_->notifyPendingWriteOnConnection(&writeCallback_).hasError());
  evb_.loop();
  EXPECT_TRUE(
      transport_->notifyPendingWriteOnConnection(&writeCallback_).hasError());
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamTwice) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the stream flow control to have no bytes remaining.
  stream->currentWriteOffset = stream->flowControlState.peerAdvertisedMaxOffset;

  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _)).Times(0);
  EXPECT_FALSE(
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_)
          .hasError());
  evb_.loop();
  EXPECT_TRUE(
      transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_)
          .hasError());
  evb_.loop();
}

TEST_F(QuicTransportTest, NotifyPendingWriteConnDuringClose) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamId2 = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  // Artificially restrict the conn flow control to have no bytes remaining.
  updateFlowControlOnWriteToStream(
      *stream, conn.flowControlState.peerAdvertisedMaxOffset);

  transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  transport_->notifyPendingWriteOnStream(streamId2, &writeCallback_);
  evb_.loop();

  EXPECT_CALL(writeCallback_, onStreamWriteReady(_, _))
      .WillOnce(Invoke([&](auto id, auto) {
        if (id == streamId) {
          EXPECT_CALL(writeCallback_, onStreamWriteError(streamId2, _));
        } else {
          EXPECT_CALL(writeCallback_, onStreamWriteError(streamId, _));
        }
        transport_->close(folly::none);
      }));
  PacketNum num = 10;
  // Give the conn some headroom.
  handleConnWindowUpdate(
      conn,
      MaxDataFrame(conn.flowControlState.peerAdvertisedMaxOffset + 1000),
      num);
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, NotifyPendingWriteStreamDuringClose) {
  auto streamId = transport_->createBidirectionalStream().value();
  auto streamId2 = transport_->createBidirectionalStream().value();
  auto& conn = transport_->getConnectionState();

  auto stream = conn.streamManager->getStream(streamId);
  auto stream2 = conn.streamManager->getStream(streamId2);
  // Artificially restrict the stream flow control to have no bytes remaining.
  stream->currentWriteOffset = stream->flowControlState.peerAdvertisedMaxOffset;
  stream2->currentWriteOffset =
      stream2->flowControlState.peerAdvertisedMaxOffset;

  transport_->notifyPendingWriteOnStream(stream->id, &writeCallback_);
  transport_->notifyPendingWriteOnStream(streamId2, &writeCallback_);
  evb_.loop();

  PacketNum num = 10;
  handleStreamWindowUpdate(
      *stream, stream->flowControlState.peerAdvertisedMaxOffset + 1000, num);

  EXPECT_CALL(connCallback_, onFlowControlUpdate(stream->id));
  EXPECT_CALL(writeCallback_, onStreamWriteError(streamId2, _));
  EXPECT_CALL(writeCallback_, onStreamWriteReady(stream->id, _))
      .WillOnce(Invoke([&](auto, auto) { transport_->close(folly::none); }));
  transport_->onNetworkData(
      SocketAddress("::1", 10000),
      NetworkData(IOBuf::copyBuffer("fake data"), Clock::now()));
}

TEST_F(QuicTransportTest, WriteStreamFromMiddleOfMap) {
  // Testing writing to multiple streams
  auto& conn = transport_->getConnectionState();
  auto s1 = transport_->createBidirectionalStream().value();
  auto s2 = transport_->createBidirectionalStream().value();

  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  uint64_t writableBytes = kDefaultUDPSendPacketLen - 100;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Invoke([&]() {
        auto res = writableBytes;
        writableBytes = 0;
        return res;
      }));

  auto stream1 = conn.streamManager->getStream(s1);
  auto buf1 = buildRandomInputData(kDefaultUDPSendPacketLen);
  writeDataToQuicStream(*stream1, buf1->clone(), false);

  auto buf2 = buildRandomInputData(kDefaultUDPSendPacketLen);
  auto stream2 = conn.streamManager->getStream(s2);
  writeDataToQuicStream(*stream2, buf2->clone(), false);

  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, conn.outstandingPackets.size());
  auto& packet = *getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  EXPECT_EQ(1, packet.packet.frames.size());
  auto& frame = packet.packet.frames.front();
  const WriteStreamFrame* streamFrame = boost::get<WriteStreamFrame>(&frame);
  EXPECT_TRUE(streamFrame);
  EXPECT_EQ(streamFrame->streamId, s1);
  conn.outstandingPackets.clear();

  // Start from stream2 instead of stream1
  conn.schedulingState.lastScheduledStream = s2;
  writableBytes = kDefaultUDPSendPacketLen - 100;

  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, conn.outstandingPackets.size());
  auto& packet2 = *getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  EXPECT_EQ(1, packet2.packet.frames.size());
  auto& frame2 = packet2.packet.frames.front();
  const WriteStreamFrame* streamFrame2 = boost::get<WriteStreamFrame>(&frame2);
  EXPECT_TRUE(streamFrame2);
  EXPECT_EQ(streamFrame2->streamId, s2);
  conn.outstandingPackets.clear();

  // Test wrap around
  conn.schedulingState.lastScheduledStream = s2;
  writableBytes = kDefaultUDPSendPacketLen;
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Invoke(bufLength));
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_EQ(1, conn.outstandingPackets.size());
  auto& packet3 = *getFirstOutstandingPacket(conn, PacketNumberSpace::AppData);
  EXPECT_EQ(2, packet3.packet.frames.size());
  auto& frame3 = packet3.packet.frames.front();
  auto& frame4 = packet3.packet.frames.back();
  const WriteStreamFrame* streamFrame3 = boost::get<WriteStreamFrame>(&frame3);
  EXPECT_TRUE(streamFrame3);
  EXPECT_EQ(streamFrame3->streamId, s2);
  const WriteStreamFrame* streamFrame4 = boost::get<WriteStreamFrame>(&frame4);
  EXPECT_TRUE(streamFrame4);
  EXPECT_EQ(streamFrame4->streamId, s1);
  transport_->close(folly::none);
}

TEST_F(QuicTransportTest, NoStream) {
  auto& conn = transport_->getConnectionState();
  EventBase evb;
  writeQuicDataToSocket(
      *socket_,
      conn,
      *conn.clientConnectionId,
      *conn.serverConnectionId,
      *aead_,
      *headerCipher_,
      transport_->getVersion(),
      conn.transportSettings.writeConnectionDataPacketsLimit);
  EXPECT_TRUE(conn.outstandingPackets.empty());
}

TEST_F(QuicTransportTest, CancelAckTimeout) {
  transport_->getTimer()->scheduleTimeout(
      transport_->getAckTimeout(), 1000000ms);
  EXPECT_TRUE(transport_->getAckTimeout()->isScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = false;
  transport_->onNetworkData(
      SocketAddress("::1", 10128),
      NetworkData(IOBuf::copyBuffer("MTA New York Service"), Clock::now()));
  EXPECT_FALSE(transport_->getAckTimeout()->isScheduled());
}

TEST_F(QuicTransportTest, ScheduleAckTimeout) {
  // Make srtt large so we will use kMinAckTimeout
  transport_->getConnectionState().lossState.srtt = 25000000us;
  EXPECT_FALSE(transport_->getAckTimeout()->isScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = true;
  transport_->onNetworkData(
      SocketAddress("::1", 10003),
      NetworkData(
          IOBuf::copyBuffer("Never on time, always timeout"), Clock::now()));
  EXPECT_TRUE(transport_->getAckTimeout()->isScheduled());
  EXPECT_NEAR(transport_->getAckTimeout()->getTimeRemaining().count(), 25, 5);
}

TEST_F(QuicTransportTest, CloseTransportCancelsAckTimeout) {
  transport_->getConnectionState().lossState.srtt = 25000000us;
  EXPECT_FALSE(transport_->getAckTimeout()->isScheduled());
  transport_->getConnectionState().pendingEvents.scheduleAckTimeout = true;
  transport_->onNetworkData(
      SocketAddress("::1", 10003),
      NetworkData(
          IOBuf::copyBuffer("Never on time, always timeout"), Clock::now()));
  EXPECT_TRUE(transport_->getAckTimeout()->isScheduled());
  // We need to send some packets, otherwise loss timer won't be scheduled
  auto stream = transport_->createBidirectionalStream().value();
  auto buf = buildRandomInputData(kDefaultUDPSendPacketLen + 20);
  folly::IOBuf passedIn;
  EXPECT_CALL(*socket_, write(_, _)).WillRepeatedly(Invoke(bufLength));
  transport_->writeChain(stream, buf->clone(), false, false);
  loopForWrites();
  transport_->scheduleLossTimeout(500ms);
  EXPECT_TRUE(transport_->isLossTimeoutScheduled());

  transport_->closeNow(folly::none);
  EXPECT_FALSE(transport_->getAckTimeout()->isScheduled());
  EXPECT_FALSE(transport_->isLossTimeoutScheduled());
}

TEST_F(QuicTransportTest, DrainTimeoutExpired) {
  EXPECT_CALL(*socket_, pauseRead()).Times(1);
  EXPECT_CALL(*socket_, close()).Times(1);
  transport_->drainImmediately();
}

TEST_F(QuicTransportTest, CloseWithDrainWillKeepSocketAround) {
  EXPECT_CALL(*socket_, pauseRead()).Times(0);
  EXPECT_CALL(*socket_, close()).Times(0);
  transport_->close(folly::none);

  // Manual shut it, otherwise transport_'s dtor will shut the socket and mess
  // up the EXPECT_CALLs above
  EXPECT_CALL(*socket_, pauseRead()).Times(1);
  EXPECT_CALL(*socket_, close()).Times(1);
  transport_->drainImmediately();
}

TEST_F(QuicTransportTest, PacedWriteNoDataToWrite) {
  ASSERT_FALSE(shouldWriteData(transport_->getConnectionState()));
  EXPECT_CALL(*socket_, write(_, _)).Times(0);
  transport_->pacedWrite(true);
}

TEST_F(QuicTransportTest, PacingWillBurstFirst) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  conn.transportSettings.pacingEnabled = true;
  conn.canBePaced = true;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(100));
  EXPECT_CALL(*rawCongestionController, canBePaced())
      .WillRepeatedly(Return(true));

  auto buf = buildRandomInputData(200);
  auto streamId = transport_->createBidirectionalStream().value();
  transport_->writeChain(streamId, buf->clone(), false, false);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Return(0));
  EXPECT_CALL(*rawCongestionController, getPacingRate(_))
      .WillRepeatedly(Return(1));
  transport_->pacedWrite(true);
}

TEST_F(QuicTransportTest, AlreadyScheduledPacingNoWrite) {
  transport_->setPacingTimer(TimerHighRes::newTimer(&evb_, 1ms));
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  conn.transportSettings.pacingEnabled = true;
  conn.canBePaced = true;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(100));
  EXPECT_CALL(*rawCongestionController, canBePaced())
      .WillRepeatedly(Return(true));

  auto buf = buildRandomInputData(200);
  auto streamId = transport_->createBidirectionalStream().value();
  transport_->writeChain(streamId, buf->clone(), false, false);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Return(0));
  EXPECT_CALL(*rawCongestionController, getPacingRate(_))
      .WillRepeatedly(Return(1));
  EXPECT_CALL(*rawCongestionController, markPacerTimeoutScheduled(_));
  EXPECT_CALL(*rawCongestionController, getPacingInterval())
      .WillRepeatedly(Return(3600000ms));
  // This will write out 100 bytes, leave 100 bytes behind. FunctionLooper will
  // schedule a pacing timeout.
  loopForWrites();

  ASSERT_TRUE(shouldWriteData(conn));
  EXPECT_TRUE(transport_->isPacingScheduled());
  EXPECT_CALL(*socket_, write(_, _)).Times(0);
  transport_->pacedWrite(true);
}

TEST_F(QuicTransportTest, NoScheduleIfNoNewData) {
  auto& conn = transport_->getConnectionState();
  auto mockCongestionController = std::make_unique<MockCongestionController>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  conn.transportSettings.pacingEnabled = true;
  conn.canBePaced = true;
  EXPECT_CALL(*rawCongestionController, getWritableBytes())
      .WillRepeatedly(Return(1000));
  EXPECT_CALL(*rawCongestionController, canBePaced())
      .WillRepeatedly(Return(true));

  auto buf = buildRandomInputData(200);
  auto streamId = transport_->createBidirectionalStream().value();
  transport_->writeChain(streamId, buf->clone(), false, false);
  EXPECT_CALL(*socket_, write(_, _)).WillOnce(Return(0));
  EXPECT_CALL(*rawCongestionController, getPacingRate(_))
      .WillRepeatedly(Return(1));
  // This will write out everything. After that because there is no new data,
  // FunctionLooper won't schedule a pacing timeout.
  transport_->pacedWrite(true);

  ASSERT_FALSE(shouldWriteData(conn));
  EXPECT_FALSE(transport_->isPacingScheduled());
}

} // namespace test
} // namespace quic
