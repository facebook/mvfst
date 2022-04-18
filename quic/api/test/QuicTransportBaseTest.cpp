/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/test/Mocks.h>

#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>

#include <quic/api/QuicSocket.h>
#include <quic/api/QuicTransportBase.h>
#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/DatagramHandlers.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/test/Mocks.h>

#include <folly/io/async/test/MockAsyncUDPSocket.h>

using namespace testing;
using namespace folly;

namespace quic {
namespace test {

constexpr uint8_t kStreamIncrement = 0x04;
using ByteEvent = QuicTransportBase::ByteEvent;
using ByteEventCancellation = QuicTransportBase::ByteEventCancellation;

enum class TestFrameType : uint8_t {
  STREAM,
  CRYPTO,
  EXPIRED_DATA,
  REJECTED_DATA,
  MAX_STREAMS,
  DATAGRAM
};

// A made up encoding decoding of a stream.
Buf encodeStreamBuffer(StreamId id, StreamBuffer data) {
  auto buf = IOBuf::create(10);
  folly::io::Appender appender(buf.get(), 10);
  appender.writeBE(static_cast<uint8_t>(TestFrameType::STREAM));
  appender.writeBE(id);
  auto dataBuf = data.data.move();
  dataBuf->coalesce();
  appender.writeBE<uint32_t>(dataBuf->length());
  appender.push(dataBuf->coalesce());
  appender.writeBE<uint64_t>(data.offset);
  appender.writeBE<uint8_t>(data.eof);
  return buf;
}

Buf encodeCryptoBuffer(StreamBuffer data) {
  auto buf = IOBuf::create(10);
  folly::io::Appender appender(buf.get(), 10);
  appender.writeBE(static_cast<uint8_t>(TestFrameType::CRYPTO));
  auto dataBuf = data.data.move();
  dataBuf->coalesce();
  appender.writeBE<uint32_t>(dataBuf->length());
  appender.push(dataBuf->coalesce());
  appender.writeBE<uint64_t>(data.offset);
  return buf;
}

// A made up encoding of a MaxStreamsFrame.
Buf encodeMaxStreamsFrame(const MaxStreamsFrame& frame) {
  auto buf = IOBuf::create(25);
  folly::io::Appender appender(buf.get(), 25);
  appender.writeBE(static_cast<uint8_t>(TestFrameType::MAX_STREAMS));
  appender.writeBE<uint8_t>(frame.isForBidirectionalStream() ? 1 : 0);
  appender.writeBE<uint64_t>(frame.maxStreams);
  return buf;
}

// Build a datagram frame
Buf encodeDatagramFrame(BufQueue data) {
  auto buf = IOBuf::create(10);
  folly::io::Appender appender(buf.get(), 10);
  appender.writeBE(static_cast<uint8_t>(TestFrameType::DATAGRAM));
  auto dataBuf = data.move();
  dataBuf->coalesce();
  appender.writeBE<uint32_t>(dataBuf->length());
  appender.push(dataBuf->coalesce());
  return buf;
}

std::pair<Buf, uint32_t> decodeDatagramFrame(folly::io::Cursor& cursor) {
  Buf outData;
  auto len = cursor.readBE<uint32_t>();
  cursor.clone(outData, len);
  return std::make_pair(std::move(outData), len);
}

std::pair<Buf, uint64_t> decodeDataBuffer(folly::io::Cursor& cursor) {
  Buf outData;
  auto len = cursor.readBE<uint32_t>();
  cursor.clone(outData, len);
  uint64_t offset = cursor.readBE<uint64_t>();
  return std::make_pair(std::move(outData), offset);
}

std::pair<StreamId, StreamBuffer> decodeStreamBuffer(
    folly::io::Cursor& cursor) {
  auto streamId = cursor.readBE<StreamId>();
  auto dataBuffer = decodeDataBuffer(cursor);
  bool eof = (bool)cursor.readBE<uint8_t>();
  return std::make_pair(
      streamId,
      StreamBuffer(std::move(dataBuffer.first), dataBuffer.second, eof));
}

StreamBuffer decodeCryptoBuffer(folly::io::Cursor& cursor) {
  auto dataBuffer = decodeDataBuffer(cursor);
  return StreamBuffer(std::move(dataBuffer.first), dataBuffer.second, false);
}

MaxStreamsFrame decodeMaxStreamsFrame(folly::io::Cursor& cursor) {
  bool isBidi = cursor.readBE<uint8_t>();
  auto maxStreams = cursor.readBE<uint64_t>();
  return MaxStreamsFrame(maxStreams, isBidi);
}

class TestPingCallback : public QuicSocket::PingCallback {
 public:
  void pingAcknowledged() noexcept override {}
  void pingTimeout() noexcept override {}
  void onPing() noexcept override {}
};

class TestByteEventCallback : public QuicSocket::ByteEventCallback {
 public:
  using HashFn = std::function<size_t(const ByteEvent&)>;
  using ComparatorFn = std::function<bool(const ByteEvent&, const ByteEvent&)>;

  enum class Status { REGISTERED = 1, RECEIVED = 2, CANCELLED = 3 };

  void onByteEventRegistered(ByteEvent event) override {
    EXPECT_TRUE(byteEventTracker_.find(event) == byteEventTracker_.end());
    byteEventTracker_[event] = Status::REGISTERED;
  }
  void onByteEvent(ByteEvent event) override {
    EXPECT_TRUE(byteEventTracker_.find(event) != byteEventTracker_.end());
    byteEventTracker_[event] = Status::RECEIVED;
  }
  void onByteEventCanceled(ByteEventCancellation cancellation) override {
    const ByteEvent& event = cancellation;
    EXPECT_TRUE(byteEventTracker_.find(event) != byteEventTracker_.end());
    byteEventTracker_[event] = Status::CANCELLED;
  }

  std::unordered_map<ByteEvent, Status, HashFn, ComparatorFn>
  getByteEventTracker() const {
    return byteEventTracker_;
  }

 private:
  // Custom hash and comparator functions that use only id, offset and types
  // (not the srtt)
  HashFn hash = [](const ByteEvent& e) {
    return folly::hash::hash_combine(e.id, e.offset, e.type);
  };
  ComparatorFn comparator = [](const ByteEvent& lhs, const ByteEvent& rhs) {
    return (
        (lhs.id == rhs.id) && (lhs.offset == rhs.offset) &&
        (lhs.type == rhs.type));
  };
  std::unordered_map<ByteEvent, Status, HashFn, ComparatorFn> byteEventTracker_{
      /* bucket count */ 4,
      hash,
      comparator};
};

static auto
getByteEventMatcher(ByteEvent::Type type, StreamId id, uint64_t offset) {
  return AllOf(
      testing::Field(&ByteEvent::type, testing::Eq(type)),
      testing::Field(&ByteEvent::id, testing::Eq(id)),
      testing::Field(&ByteEvent::offset, testing::Eq(offset)));
}

static auto getByteEventTrackerMatcher(
    ByteEvent event,
    TestByteEventCallback::Status status) {
  return Pair(getByteEventMatcher(event.type, event.id, event.offset), status);
}

class TestQuicTransport
    : public QuicTransportBase,
      public std::enable_shared_from_this<TestQuicTransport> {
 public:
  TestQuicTransport(
      folly::EventBase* evb,
      std::unique_ptr<folly::AsyncUDPSocket> socket,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connCb)
      : QuicTransportBase(evb, std::move(socket)),
        observerContainer_(std::make_shared<SocketObserverContainer>(this)) {
    setConnectionSetupCallback(connSetupCb);
    setConnectionCallback(connCb);
    auto conn = std::make_unique<QuicServerConnectionState>(
        FizzServerQuicHandshakeContext::Builder().build());
    conn->clientConnectionId = ConnectionId({10, 9, 8, 7});
    conn->version = QuicVersion::MVFST;
    conn->observerContainer = observerContainer_;
    transportConn = conn.get();
    conn_.reset(conn.release());
    aead = test::createNoOpAead();
    headerCipher = test::createNoOpHeaderCipher();
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
  }

  ~TestQuicTransport() override {
    resetConnectionCallbacks();
    // we need to call close in the derived class.
    closeImpl(
        QuicError(
            QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
            std::string("shutdown")),
        false);
  }

  std::chrono::milliseconds getLossTimeoutRemainingTime() const {
    return lossTimeout_.getTimeRemaining();
  }

  void onReadData(const folly::SocketAddress&, NetworkDataSingle&& data)
      override {
    if (!data.data) {
      return;
    }
    folly::io::Cursor cursor(data.data.get());
    while (!cursor.isAtEnd()) {
      // create server chosen connId with processId = 0 and workerId = 0
      ServerConnectionIdParams params(0, 0, 0);
      conn_->serverConnectionId = *connIdAlgo_->encodeConnectionId(params);
      auto type = static_cast<TestFrameType>(cursor.readBE<uint8_t>());
      if (type == TestFrameType::CRYPTO) {
        auto cryptoBuffer = decodeCryptoBuffer(cursor);
        appendDataToReadBuffer(
            conn_->cryptoState->initialStream, std::move(cryptoBuffer));
      } else if (type == TestFrameType::MAX_STREAMS) {
        auto maxStreamsFrame = decodeMaxStreamsFrame(cursor);
        if (maxStreamsFrame.isForBidirectionalStream()) {
          conn_->streamManager->setMaxLocalBidirectionalStreams(
              maxStreamsFrame.maxStreams);
        } else {
          conn_->streamManager->setMaxLocalUnidirectionalStreams(
              maxStreamsFrame.maxStreams);
        }
      } else if (type == TestFrameType::DATAGRAM) {
        auto buffer = decodeDatagramFrame(cursor);
        auto frame = DatagramFrame(buffer.second, std::move(buffer.first));
        handleDatagram(*conn_, frame, data.receiveTimePoint);
      } else {
        auto buffer = decodeStreamBuffer(cursor);
        QuicStreamState* stream = conn_->streamManager->getStream(buffer.first);
        if (!stream) {
          continue;
        }
        appendDataToReadBuffer(*stream, std::move(buffer.second));
        conn_->streamManager->updateReadableStreams(*stream);
        conn_->streamManager->updatePeekableStreams(*stream);
      }
    }
  }

  void writeData() override {
    writeQuicDataToSocket(
        *socket_,
        *conn_,
        *conn_->serverConnectionId,
        *conn_->clientConnectionId,
        *aead,
        *headerCipher,
        *conn_->version,
        conn_->transportSettings.writeConnectionDataPacketsLimit);
  }

  bool hasWriteCipher() const {
    return conn_->oneRttWriteCipher != nullptr;
  }

  std::shared_ptr<QuicTransportBase> sharedGuard() override {
    return shared_from_this();
  }

  QuicConnectionStateBase& getConnectionState() {
    return *conn_;
  }

  void closeTransport() {
    transportClosed = true;
  }

  void AckTimeout() {
    ackTimeoutExpired();
  }

  void setIdleTimeout() {
    setIdleTimer();
  }

  void invokeIdleTimeout() {
    idleTimeout_.timeoutExpired();
  }

  void invokeAckTimeout() {
    ackTimeout_.timeoutExpired();
  }

  void invokeSendPing(std::chrono::milliseconds interval) {
    sendPing(interval);
  }

  void invokeCancelPingTimeout() {
    pingTimeout_.cancelTimeout();
  }

  void invokeHandlePingCallbacks() {
    handlePingCallbacks();
  }

  void invokeHandleKnobCallbacks() {
    handleKnobCallbacks();
  }

  bool isPingTimeoutScheduled() {
    if (pingTimeout_.isScheduled()) {
      return true;
    }
    return false;
  }

  auto& writeLooper() {
    return writeLooper_;
  }

  void unbindConnection() {}

  void onReadError(const folly::AsyncSocketException&) noexcept {}

  void addDataToStream(StreamId id, StreamBuffer data) {
    auto buf = encodeStreamBuffer(id, std::move(data));
    SocketAddress addr("127.0.0.1", 1000);
    onNetworkData(addr, NetworkData(std::move(buf), Clock::now()));
  }

  void addCryptoData(StreamBuffer data) {
    auto buf = encodeCryptoBuffer(std::move(data));
    SocketAddress addr("127.0.0.1", 1000);
    onNetworkData(addr, NetworkData(std::move(buf), Clock::now()));
  }

  void addMaxStreamsFrame(MaxStreamsFrame frame) {
    auto buf = encodeMaxStreamsFrame(frame);
    SocketAddress addr("127.0.0.1", 1000);
    onNetworkData(addr, NetworkData(std::move(buf), Clock::now()));
  }

  void addStreamReadError(StreamId id, QuicErrorCode ex) {
    QuicStreamState* stream = conn_->streamManager->getStream(id);
    stream->streamReadError = ex;
    conn_->streamManager->updateReadableStreams(*stream);
    conn_->streamManager->updatePeekableStreams(*stream);
    // peekableStreams is updated to contain streams with streamReadError
    updatePeekLooper();
    updateReadLooper();
  }

  void addDatagram(Buf data, TimePoint recvTime = Clock::now()) {
    auto buf = encodeDatagramFrame(std::move(data));
    SocketAddress addr("127.0.0.1", 1000);
    onNetworkData(addr, NetworkData(std::move(buf), recvTime));
  }

  void closeStream(StreamId id) {
    QuicStreamState* stream = conn_->streamManager->getStream(id);
    stream->sendState = StreamSendState::Closed;
    stream->recvState = StreamRecvState::Closed;
    conn_->streamManager->addClosed(id);

    auto deliveryCb = deliveryCallbacks_.find(id);
    if (deliveryCb != deliveryCallbacks_.end()) {
      for (auto& cbs : deliveryCb->second) {
        ByteEvent event = {};
        event.id = id;
        event.offset = cbs.offset;
        event.type = ByteEvent::Type::ACK;
        event.srtt = stream->conn.lossState.srtt;
        cbs.callback->onByteEvent(event);
        if (closeState_ != CloseState::OPEN) {
          break;
        }
      }
      deliveryCallbacks_.erase(deliveryCb);
    }

    auto txCallbacksForStream = txCallbacks_.find(id);
    if (txCallbacksForStream != txCallbacks_.end()) {
      for (auto& cbs : txCallbacksForStream->second) {
        ByteEvent event = {};
        event.id = id;
        event.offset = cbs.offset;
        event.type = ByteEvent::Type::TX;
        cbs.callback->onByteEvent(event);
        if (closeState_ != CloseState::OPEN) {
          break;
        }
      }
      txCallbacks_.erase(txCallbacksForStream);
    }

    SocketAddress addr("127.0.0.1", 1000);
    // some fake data to trigger close behavior.
    auto buf = encodeStreamBuffer(
        id,
        StreamBuffer(IOBuf::create(0), stream->maxOffsetObserved + 1, true));
    auto networkData = NetworkData(std::move(buf), Clock::now());
    onNetworkData(addr, std::move(networkData));
  }

  QuicStreamState* getStream(StreamId id) {
    return conn_->streamManager->getStream(id);
  }

  void setServerConnectionId() {
    // create server chosen connId with processId = 0 and workerId = 0
    ServerConnectionIdParams params(0, 0, 0);
    conn_->serverConnectionId = *connIdAlgo_->encodeConnectionId(params);
  }

  void driveReadCallbacks() {
    getEventBase()->loopOnce();
  }

  QuicErrorCode getConnectionError() {
    return conn_->localConnectionError->code;
  }

  bool isClosed() const noexcept {
    return closeState_ == CloseState::CLOSED;
  }

  void closeWithoutWrite() {
    closeImpl(folly::none, false, false);
  }

  void invokeWriteSocketData() {
    writeSocketData();
  }

  void invokeProcessCallbacksAfterNetworkData() {
    processCallbacksAfterNetworkData();
  }

  // Simulates the delivery of a Byte Event callback, similar to the way it
  // happens in QuicTransportBase::processCallbacksAfterNetworkData() or
  // in the runOnEvbAsync lambda in
  // QuicTransportBase::registerByteEventCallback()
  bool deleteRegisteredByteEvent(
      StreamId id,
      uint64_t offset,
      ByteEventCallback* cb,
      ByteEvent::Type type) {
    auto& byteEventMap = getByteEventMap(type);
    auto streamByteEventCbIt = byteEventMap.find(id);
    if (streamByteEventCbIt == byteEventMap.end()) {
      return false;
    }
    auto pos = std::find_if(
        streamByteEventCbIt->second.begin(),
        streamByteEventCbIt->second.end(),
        [offset, cb](const ByteEventDetail& p) {
          return ((p.offset == offset) && (p.callback == cb));
        });
    if (pos == streamByteEventCbIt->second.end()) {
      return false;
    }
    streamByteEventCbIt->second.erase(pos);
    return true;
  }

  void enableDatagram() {
    conn_->datagramState.maxReadFrameSize = 65535;
    conn_->datagramState.maxReadBufferSize = 10;
  }

  SocketObserverContainer* getSocketObserverContainer() const override {
    return observerContainer_.get();
  }

  QuicServerConnectionState* transportConn;
  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
  std::unique_ptr<ConnectionIdAlgo> connIdAlgo_;
  bool transportClosed{false};
  PacketNum packetNum_{0};

  // Container of observers for the socket / transport.
  //
  // This member MUST be last in the list of members to ensure it is destroyed
  // first, before any other members are destroyed. This ensures that observers
  // can inspect any socket / transport state available through public methods
  // when destruction of the transport begins.
  const std::shared_ptr<SocketObserverContainer> observerContainer_;
};

class QuicTransportImplTest : public Test {
 public:
  void SetUp() override {
    evb = std::make_unique<folly::EventBase>();
    auto socket =
        std::make_unique<NiceMock<folly::test::MockAsyncUDPSocket>>(evb.get());
    socketPtr = socket.get();
    transport = std::make_shared<TestQuicTransport>(
        evb.get(), std::move(socket), &connSetupCallback, &connCallback);
    auto& conn = *transport->transportConn;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamWindowSize;
    conn.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionWindowSize;
    conn.streamManager->setMaxLocalBidirectionalStreams(
        kDefaultMaxStreamsBidirectional);
    conn.streamManager->setMaxLocalUnidirectionalStreams(
        kDefaultMaxStreamsUnidirectional);
  }

  auto getTxMatcher(StreamId id, uint64_t offset) {
    return MockByteEventCallback::getTxMatcher(id, offset);
  }

  auto getAckMatcher(StreamId id, uint64_t offset) {
    return MockByteEventCallback::getAckMatcher(id, offset);
  }

 protected:
  std::unique_ptr<folly::EventBase> evb;
  NiceMock<MockConnectionSetupCallback> connSetupCallback;
  NiceMock<MockConnectionCallback> connCallback;
  TestByteEventCallback byteEventCallback;
  std::shared_ptr<TestQuicTransport> transport;
  folly::test::MockAsyncUDPSocket* socketPtr;
};

class QuicTransportImplTestClose : public QuicTransportImplTest,
                                   public testing::WithParamInterface<bool> {};

INSTANTIATE_TEST_SUITE_P(
    QuicTransportImplTest,
    QuicTransportImplTestClose,
    Values(true, false));

TEST_F(QuicTransportImplTest, AckTimeoutExpiredWillResetTimeoutFlag) {
  transport->invokeAckTimeout();
  EXPECT_FALSE(transport->transportConn->pendingEvents.scheduleAckTimeout);
}

TEST_F(QuicTransportImplTest, IdleTimeoutExpiredDestroysTransport) {
  EXPECT_CALL(connSetupCallback, onConnectionSetupError(_))
      .WillOnce(Invoke([&](auto) { transport = nullptr; }));
  transport->invokeIdleTimeout();
}

TEST_F(QuicTransportImplTest, IdleTimeoutStreamMaessage) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  auto stream3 = transport->createUnidirectionalStream().value();
  transport->setControlStream(stream3);

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  transport->setReadCallback(stream1, &readCb1);
  transport->setReadCallback(stream2, &readCb2);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10));
  EXPECT_CALL(readCb1, readError(stream1, _))
      .Times(1)
      .WillOnce(Invoke([](auto, auto error) {
        EXPECT_EQ("Idle timeout, num non control streams: 2", error.message);
      }));
  transport->invokeIdleTimeout();
}

TEST_F(QuicTransportImplTest, WriteAckPacketUnsetsLooper) {
  // start looper in running state first
  transport->writeLooper()->run(true);

  // Write data which will be acked immediately.
  PacketNum packetSeen = 10;
  bool pktHasRetransmittableData = true;
  bool pktHasCryptoData = true;
  updateAckState(
      *transport->transportConn,
      PacketNumberSpace::Initial,
      packetSeen,
      pktHasRetransmittableData,
      pktHasCryptoData,
      Clock::now());
  ASSERT_TRUE(transport->transportConn->ackStates.initialAckState
                  .needsToSendAckImmediately);
  // Trigger the loop callback. This will trigger writes and we assume this will
  // write the acks since we have nothing else to write.
  transport->writeLooper()->runLoopCallback();
  EXPECT_FALSE(transport->transportConn->pendingEvents.scheduleAckTimeout);
  EXPECT_FALSE(transport->writeLooper()->isLoopCallbackScheduled());
}

TEST_F(QuicTransportImplTest, ReadCallbackDataAvailable) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  StreamId stream3 = 0x6;

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;
  NiceMock<MockReadCallback> readCb3;

  transport->setReadCallback(stream1, &readCb1);
  transport->setReadCallback(stream2, &readCb2);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10));

  transport->addDataToStream(
      stream3, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->setReadCallback(stream3, &readCb3);

  EXPECT_CALL(readCb1, readAvailable(stream1));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->driveReadCallbacks();

  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(readCb1, readAvailable(stream1));
  EXPECT_CALL(readCb2, readAvailable(stream2));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->driveReadCallbacks();

  EXPECT_CALL(readCb1, readAvailable(stream1));
  EXPECT_CALL(readCb2, readAvailable(stream2));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->driveReadCallbacks();

  EXPECT_CALL(readCb2, readAvailable(stream2));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->setReadCallback(stream1, nullptr);
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadCallbackDataAvailableNoReap) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  StreamId stream3 = 0x6;

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;
  NiceMock<MockReadCallback> readCb3;

  transport->setReadCallback(stream1, &readCb1);
  transport->setReadCallback(stream2, &readCb2);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10));

  transport->addDataToStream(
      stream3, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->driveReadCallbacks();

  transport->setReadCallback(stream3, &readCb3);
  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(readCb1, readAvailable(stream1));
  EXPECT_CALL(readCb2, readAvailable(stream2));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->driveReadCallbacks();

  EXPECT_CALL(readCb1, readAvailable(stream1));
  EXPECT_CALL(readCb2, readAvailable(stream2));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->driveReadCallbacks();

  EXPECT_CALL(readCb2, readAvailable(stream2));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->setReadCallback(stream1, nullptr);
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadCallbackDataAvailableOrdered) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.orderedReadCallbacks = true;
  transport->setTransportSettings(transportSettings);

  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  StreamId stream3 = 0x6;

  InSequence s;
  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;
  NiceMock<MockReadCallback> readCb3;

  transport->setReadCallback(stream1, &readCb1);
  transport->setReadCallback(stream2, &readCb2);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10));

  transport->addDataToStream(
      stream3, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->setReadCallback(stream3, &readCb3);

  EXPECT_CALL(readCb1, readAvailable(stream1));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->driveReadCallbacks();

  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(readCb1, readAvailable(stream1));
  EXPECT_CALL(readCb2, readAvailable(stream2));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->driveReadCallbacks();

  EXPECT_CALL(readCb1, readAvailable(stream1));
  EXPECT_CALL(readCb2, readAvailable(stream2));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->driveReadCallbacks();

  EXPECT_CALL(readCb2, readAvailable(stream2));
  EXPECT_CALL(readCb3, readAvailable(stream3));
  transport->setReadCallback(stream1, nullptr);
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadCallbackChangeReadCallback) {
  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  EXPECT_TRUE(transport->setReadCallback(stream1, nullptr).hasError());

  transport->setReadCallback(stream1, &readCb1);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->driveReadCallbacks();

  transport->setReadCallback(stream1, &readCb2);
  EXPECT_CALL(readCb2, readAvailable(stream1));
  transport->driveReadCallbacks();

  auto& conn = transport->getConnectionState();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  transport->setReadCallback(stream1, nullptr);
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  EXPECT_CALL(readCb2, readAvailable(_)).Times(0);
  transport->driveReadCallbacks();

  EXPECT_TRUE(transport->setReadCallback(stream1, &readCb2).hasError());

  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadCallbackUnsetAll) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  // Set the read callbacks, and then add data to the stream, and see that the
  // callbacks are, in fact, called.

  transport->setReadCallback(stream1, &readCb1);
  transport->setReadCallback(stream2, &readCb2);

  EXPECT_CALL(readCb1, readAvailable(stream1));
  EXPECT_CALL(readCb2, readAvailable(stream2));

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  transport->driveReadCallbacks();

  // Unset all of the read callbacks, then add data to the stream, and see that
  // the read callbacks are not called.

  transport->unsetAllReadCallbacks();

  EXPECT_CALL(readCb1, readAvailable(stream1)).Times(0);
  EXPECT_CALL(readCb2, readAvailable(stream2)).Times(0);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  transport->driveReadCallbacks();

  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadCallbackPauseResume) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  transport->setReadCallback(stream1, &readCb1);
  transport->setReadCallback(stream2, &readCb2);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  auto res = transport->pauseRead(stream1);
  EXPECT_TRUE(res);
  EXPECT_CALL(readCb1, readAvailable(stream1)).Times(0);
  EXPECT_CALL(readCb2, readAvailable(stream2));
  transport->driveReadCallbacks();

  res = transport->resumeRead(stream1);
  EXPECT_TRUE(res);
  res = transport->pauseRead(stream2);
  EXPECT_CALL(readCb1, readAvailable(stream1));
  EXPECT_CALL(readCb2, readAvailable(stream2)).Times(0);
  transport->driveReadCallbacks();

  auto stream3 = transport->createBidirectionalStream().value();
  res = transport->pauseRead(stream3);
  EXPECT_FALSE(res);
  EXPECT_EQ(LocalErrorCode::APP_ERROR, res.error());
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadCallbackNoCallbackSet) {
  auto stream1 = transport->createBidirectionalStream().value();

  transport->addDataToStream(
      stream1,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10));
  transport->driveReadCallbacks();
  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadCallbackInvalidStream) {
  NiceMock<MockReadCallback> readCb1;
  StreamId invalidStream = 10;
  EXPECT_TRUE(transport->setReadCallback(invalidStream, &readCb1).hasError());
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadData) {
  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  transport->setReadCallback(stream1, &readCb1);

  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->addDataToStream(stream1, StreamBuffer(readData->clone(), 0));
  transport->driveReadCallbacks();

  transport->read(stream1, 10).thenOrThrow([&](std::pair<Buf, bool> data) {
    IOBufEqualTo eq;
    auto expected = readData->clone();
    expected->trimEnd(expected->length() - 10);
    EXPECT_TRUE(eq(*data.first, *expected));
  });

  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->driveReadCallbacks();
  transport->read(stream1, 100).thenOrThrow([&](std::pair<Buf, bool> data) {
    IOBufEqualTo eq;
    auto expected = readData->clone();
    expected->trimStart(10);
    EXPECT_TRUE(eq(*data.first, *expected));
  });

  transport->driveReadCallbacks();
  transport.reset();
}

// TODO The finest copypasta around. We need a better story for parameterizing
// unidirectional vs. bidirectional.
TEST_F(QuicTransportImplTest, UnidirectionalReadData) {
  auto stream1 = 0x6;

  NiceMock<MockReadCallback> readCb1;
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  transport->addDataToStream(stream1, StreamBuffer(readData->clone(), 0));
  transport->setReadCallback(stream1, &readCb1);
  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->driveReadCallbacks();

  transport->read(stream1, 10).thenOrThrow([&](std::pair<Buf, bool> data) {
    IOBufEqualTo eq;
    auto expected = readData->clone();
    expected->trimEnd(expected->length() - 10);
    EXPECT_TRUE(eq(*data.first, *expected));
  });

  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->driveReadCallbacks();
  transport->read(stream1, 100).thenOrThrow([&](std::pair<Buf, bool> data) {
    IOBufEqualTo eq;
    auto expected = readData->clone();
    expected->trimStart(10);
    EXPECT_TRUE(eq(*data.first, *expected));
  });

  transport->driveReadCallbacks();
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadDataUnsetReadCallbackInCallback) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  NiceMock<MockReadCallback> readCb1;
  transport->setReadCallback(stream1, &readCb1);

  transport->addDataToStream(stream1, StreamBuffer(readData->clone(), 0, true));

  EXPECT_CALL(readCb1, readAvailable(stream1))
      .WillOnce(Invoke(
          [&](StreamId id) { transport->setReadCallback(id, nullptr); }));
  transport->driveReadCallbacks();
  transport->driveReadCallbacks();
  transport->getEventBase()->loop();
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadDataNoCallback) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  transport->addDataToStream(stream1, StreamBuffer(readData->clone(), 0, true));
  transport->driveReadCallbacks();
  transport->read(stream1, 100).thenOrThrow([&](std::pair<Buf, bool> data) {
    IOBufEqualTo eq;
    EXPECT_TRUE(eq(*data.first, *readData));
    EXPECT_TRUE(data.second);
  });
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadCallbackForClientOutOfOrderStream) {
  InSequence dummy;
  StreamId clientOutOfOrderStream = 96;
  StreamId clientOutOfOrderStream2 = 76;

  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  NiceMock<MockReadCallback> streamRead;

  for (StreamId start = 0x00; start <= clientOutOfOrderStream;
       start += kStreamIncrement) {
    EXPECT_CALL(connCallback, onNewBidirectionalStream(start))
        .WillOnce(Invoke(
            [&](StreamId id) { transport->setReadCallback(id, &streamRead); }));
  }

  EXPECT_CALL(streamRead, readAvailable(clientOutOfOrderStream))
      .WillOnce(Invoke([&](StreamId id) {
        transport->read(id, 100).thenOrThrow([&](std::pair<Buf, bool> data) {
          IOBufEqualTo eq;
          EXPECT_TRUE(eq(*data.first, *readData));
          EXPECT_TRUE(data.second);
        });
      }));

  transport->addDataToStream(
      clientOutOfOrderStream, StreamBuffer(readData->clone(), 0, true));

  transport->driveReadCallbacks();

  transport->addDataToStream(
      clientOutOfOrderStream2, StreamBuffer(readData->clone(), 0, true));

  EXPECT_CALL(streamRead, readAvailable(clientOutOfOrderStream2))
      .WillOnce(Invoke([&](StreamId id) {
        transport->read(id, 100).thenOrThrow([&](std::pair<Buf, bool> data) {
          IOBufEqualTo eq;
          EXPECT_TRUE(eq(*data.first, *readData));
          EXPECT_TRUE(data.second);
        });
      }));
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadDataInvalidStream) {
  StreamId invalidStream = 10;
  EXPECT_THROW(
      transport->read(invalidStream, 100).thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadError) {
  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  transport->setReadCallback(stream1, &readCb1);

  EXPECT_CALL(
      readCb1, readError(stream1, IsError(LocalErrorCode::STREAM_CLOSED)));
  transport->addStreamReadError(stream1, LocalErrorCode::STREAM_CLOSED);
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_F(QuicTransportImplTest, ReadCallbackDeleteTransport) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  transport->setReadCallback(stream1, &readCb1);
  transport->setReadCallback(stream2, &readCb2);

  transport->addStreamReadError(stream1, LocalErrorCode::NO_ERROR);

  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(readCb1, readError(stream1, _)).WillOnce(Invoke([&](auto, auto) {
    transport.reset();
  }));
  EXPECT_CALL(readCb2, readAvailable(stream2));
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_F(QuicTransportImplTest, onNewBidirectionalStreamCallback) {
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  StreamId stream2 = 0x00;
  EXPECT_CALL(connCallback, onNewBidirectionalStream(stream2));
  transport->addDataToStream(stream2, StreamBuffer(readData->clone(), 0, true));

  StreamId stream3 = 0x04;
  EXPECT_CALL(connCallback, onNewBidirectionalStream(stream3));
  transport->addDataToStream(stream3, StreamBuffer(readData->clone(), 0, true));

  StreamId uniStream3 = 0xa;
  EXPECT_CALL(
      connCallback,
      onNewUnidirectionalStream(uniStream3 - 2 * kStreamIncrement));
  EXPECT_CALL(
      connCallback, onNewUnidirectionalStream(uniStream3 - kStreamIncrement));
  EXPECT_CALL(connCallback, onNewUnidirectionalStream(uniStream3));
  transport->addDataToStream(
      uniStream3, StreamBuffer(readData->clone(), 0, true));
  transport.reset();
}

TEST_F(QuicTransportImplTest, onNewStreamCallbackDoesNotRemove) {
  auto readData = folly::IOBuf::copyBuffer("actual stream data");
  StreamId uniStream1 = 2;
  StreamId uniStream2 = uniStream1 + kStreamIncrement;
  EXPECT_CALL(connCallback, onNewUnidirectionalStream(uniStream1))
      .WillOnce(Invoke([&](StreamId id) {
        ASSERT_FALSE(transport->read(id, 100).hasError());
      }));
  EXPECT_CALL(connCallback, onNewUnidirectionalStream(uniStream2))
      .WillOnce(Invoke([&](StreamId id) {
        ASSERT_FALSE(transport->read(id, 100).hasError());
      }));
  transport->addDataToStream(
      uniStream1, StreamBuffer(readData->clone(), 0, true));
  transport->addDataToStream(
      uniStream2, StreamBuffer(readData->clone(), 0, true));
  transport.reset();
}

TEST_F(QuicTransportImplTest, onNewBidirectionalStreamStreamOutOfOrder) {
  InSequence dummy;
  auto readData = folly::IOBuf::copyBuffer("actual stream data");
  StreamId biStream1 = 28;
  StreamId uniStream1 = 30;
  for (StreamId id = 0x00; id <= biStream1; id += kStreamIncrement) {
    EXPECT_CALL(connCallback, onNewBidirectionalStream(id));
  }
  for (StreamId id = 0x02; id <= uniStream1; id += kStreamIncrement) {
    EXPECT_CALL(connCallback, onNewUnidirectionalStream(id));
  }
  transport->addDataToStream(
      biStream1, StreamBuffer(readData->clone(), 0, true));
  transport->addDataToStream(
      uniStream1, StreamBuffer(readData->clone(), 0, true));

  StreamId biStream2 = 56;
  StreamId uniStream2 = 38;
  for (StreamId id = biStream1 + kStreamIncrement; id <= biStream2;
       id += kStreamIncrement) {
    EXPECT_CALL(connCallback, onNewBidirectionalStream(id));
  }
  for (StreamId id = uniStream1 + kStreamIncrement; id <= uniStream2;
       id += kStreamIncrement) {
    EXPECT_CALL(connCallback, onNewUnidirectionalStream(id));
  }
  transport->addDataToStream(
      biStream2, StreamBuffer(readData->clone(), 0, true));
  transport->addDataToStream(
      uniStream2, StreamBuffer(readData->clone(), 0, true));
  transport.reset();
}

TEST_F(QuicTransportImplTest, onNewBidirectionalStreamSetReadCallback) {
  InSequence dummy;
  auto readData = folly::IOBuf::copyBuffer("actual stream data");
  transport->addCryptoData(StreamBuffer(readData->clone(), 0, true));

  NiceMock<MockReadCallback> stream2Read;
  StreamId stream2 = 0x00;
  EXPECT_CALL(connCallback, onNewBidirectionalStream(stream2))
      .WillOnce(Invoke(
          [&](StreamId id) { transport->setReadCallback(id, &stream2Read); }));
  transport->addDataToStream(stream2, StreamBuffer(readData->clone(), 0, true));

  StreamId stream3 = 0x10;
  NiceMock<MockReadCallback> streamRead;
  for (StreamId start = stream2 + kStreamIncrement; start <= stream3;
       start += kStreamIncrement) {
    EXPECT_CALL(connCallback, onNewBidirectionalStream(start))
        .WillOnce(Invoke(
            [&](StreamId id) { transport->setReadCallback(id, &streamRead); }));
  }
  transport->addDataToStream(stream3, StreamBuffer(readData->clone(), 0, true));
  evb->loopOnce();
  transport.reset();
}

TEST_F(QuicTransportImplTest, OnInvalidServerStream) {
  EXPECT_CALL(
      connSetupCallback,
      onConnectionSetupError(IsError(TransportErrorCode::STREAM_STATE_ERROR)));
  auto readData = folly::IOBuf::copyBuffer("actual stream data");
  StreamId stream1 = 29;
  transport->addDataToStream(stream1, StreamBuffer(readData->clone(), 0, true));
  EXPECT_TRUE(transport->isClosed());
  EXPECT_EQ(
      transport->getConnectionError(),
      QuicErrorCode(TransportErrorCode::STREAM_STATE_ERROR));
  transport.reset();
}

TEST_F(QuicTransportImplTest, CreateStream) {
  auto streamId = transport->createBidirectionalStream().value();
  auto streamId2 = transport->createBidirectionalStream().value();
  auto streamId3 = transport->createBidirectionalStream().value();
  auto streamId4 = transport->createBidirectionalStream().value();

  EXPECT_EQ(streamId2, streamId + kStreamIncrement);
  EXPECT_EQ(streamId3, streamId2 + kStreamIncrement);
  EXPECT_EQ(streamId4, streamId3 + kStreamIncrement);
  transport.reset();
}

TEST_F(QuicTransportImplTest, CreateUnidirectionalStream) {
  auto streamId = transport->createUnidirectionalStream().value();
  auto streamId2 = transport->createUnidirectionalStream().value();
  auto streamId3 = transport->createUnidirectionalStream().value();
  auto streamId4 = transport->createUnidirectionalStream().value();

  EXPECT_EQ(streamId2, streamId + kStreamIncrement);
  EXPECT_EQ(streamId3, streamId2 + kStreamIncrement);
  EXPECT_EQ(streamId4, streamId3 + kStreamIncrement);
  transport.reset();
}

TEST_F(QuicTransportImplTest, CreateBothStream) {
  auto uniStreamId = transport->createUnidirectionalStream().value();
  auto biStreamId = transport->createBidirectionalStream().value();
  auto uniStreamId2 = transport->createUnidirectionalStream().value();
  auto biStreamId2 = transport->createBidirectionalStream().value();
  auto uniStreamId3 = transport->createUnidirectionalStream().value();
  auto biStreamId3 = transport->createBidirectionalStream().value();
  auto uniStreamId4 = transport->createUnidirectionalStream().value();
  auto biStreamId4 = transport->createBidirectionalStream().value();

  EXPECT_EQ(uniStreamId2, uniStreamId + kStreamIncrement);
  EXPECT_EQ(uniStreamId3, uniStreamId2 + kStreamIncrement);
  EXPECT_EQ(uniStreamId4, uniStreamId3 + kStreamIncrement);
  EXPECT_EQ(biStreamId2, biStreamId + kStreamIncrement);
  EXPECT_EQ(biStreamId3, biStreamId2 + kStreamIncrement);
  EXPECT_EQ(biStreamId4, biStreamId3 + kStreamIncrement);
  transport.reset();
}

TEST_F(QuicTransportImplTest, CreateStreamLimitsBidirectionalZero) {
  transport->transportConn->streamManager->setMaxLocalBidirectionalStreams(
      0, true);
  EXPECT_EQ(transport->getNumOpenableBidirectionalStreams(), 0);
  auto result = transport->createBidirectionalStream();
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);
  result = transport->createUnidirectionalStream();
  EXPECT_TRUE(result);
  transport.reset();
}

TEST_F(QuicTransportImplTest, CreateStreamLimitsUnidirectionalZero) {
  transport->transportConn->streamManager->setMaxLocalUnidirectionalStreams(
      0, true);
  EXPECT_EQ(transport->getNumOpenableUnidirectionalStreams(), 0);
  auto result = transport->createUnidirectionalStream();
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);
  result = transport->createBidirectionalStream();
  EXPECT_TRUE(result);
  transport.reset();
}

TEST_F(QuicTransportImplTest, CreateStreamLimitsBidirectionalFew) {
  transport->transportConn->streamManager->setMaxLocalBidirectionalStreams(
      10, true);
  EXPECT_EQ(transport->getNumOpenableBidirectionalStreams(), 10);
  for (int i = 0; i < 10; i++) {
    EXPECT_TRUE(transport->createBidirectionalStream());
    EXPECT_EQ(transport->getNumOpenableBidirectionalStreams(), 10 - (i + 1));
  }
  auto result = transport->createBidirectionalStream();
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);
  EXPECT_TRUE(transport->createUnidirectionalStream());
  transport.reset();
}

TEST_F(QuicTransportImplTest, CreateStreamLimitsUnidirectionalFew) {
  transport->transportConn->streamManager->setMaxLocalUnidirectionalStreams(
      10, true);
  EXPECT_EQ(transport->getNumOpenableUnidirectionalStreams(), 10);
  for (int i = 0; i < 10; i++) {
    EXPECT_TRUE(transport->createUnidirectionalStream());
    EXPECT_EQ(transport->getNumOpenableUnidirectionalStreams(), 10 - (i + 1));
  }
  auto result = transport->createUnidirectionalStream();
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);
  EXPECT_TRUE(transport->createBidirectionalStream());
  transport.reset();
}

TEST_F(QuicTransportImplTest, onBidiStreamsAvailableCallback) {
  transport->transportConn->streamManager->setMaxLocalBidirectionalStreams(
      0, /*force=*/true);

  EXPECT_CALL(connCallback, onBidirectionalStreamsAvailable(_))
      .WillOnce(Invoke([](uint64_t numAvailableStreams) {
        EXPECT_EQ(numAvailableStreams, 1);
      }));
  transport->addMaxStreamsFrame(MaxStreamsFrame(1, /*isBidirectionalIn=*/true));
  EXPECT_EQ(transport->getNumOpenableBidirectionalStreams(), 1);

  // same value max streams frame doesn't trigger callback
  transport->addMaxStreamsFrame(MaxStreamsFrame(1, /*isBidirectionalIn=*/true));
}

TEST_F(QuicTransportImplTest, onBidiStreamsAvailableCallbackAfterExausted) {
  transport->transportConn->streamManager->setMaxLocalBidirectionalStreams(
      0, /*force=*/true);

  EXPECT_CALL(connCallback, onBidirectionalStreamsAvailable(_)).Times(2);
  transport->addMaxStreamsFrame(MaxStreamsFrame(
      1,
      /*isBidirectionalIn=*/true));
  EXPECT_EQ(transport->getNumOpenableBidirectionalStreams(), 1);

  auto result = transport->createBidirectionalStream();
  EXPECT_TRUE(result);
  EXPECT_EQ(transport->getNumOpenableBidirectionalStreams(), 0);

  transport->addMaxStreamsFrame(MaxStreamsFrame(
      2,
      /*isBidirectionalIn=*/true));
}

TEST_F(QuicTransportImplTest, oneUniStreamsAvailableCallback) {
  transport->transportConn->streamManager->setMaxLocalUnidirectionalStreams(
      0, /*force=*/true);

  EXPECT_CALL(connCallback, onUnidirectionalStreamsAvailable(_))
      .WillOnce(Invoke([](uint64_t numAvailableStreams) {
        EXPECT_EQ(numAvailableStreams, 1);
      }));
  transport->addMaxStreamsFrame(
      MaxStreamsFrame(1, /*isBidirectionalIn=*/false));
  EXPECT_EQ(transport->getNumOpenableUnidirectionalStreams(), 1);

  // same value max streams frame doesn't trigger callback
  transport->addMaxStreamsFrame(
      MaxStreamsFrame(1, /*isBidirectionalIn=*/false));
}

TEST_F(QuicTransportImplTest, onUniStreamsAvailableCallbackAfterExausted) {
  transport->transportConn->streamManager->setMaxLocalUnidirectionalStreams(
      0, /*force=*/true);

  EXPECT_CALL(connCallback, onUnidirectionalStreamsAvailable(_)).Times(2);
  transport->addMaxStreamsFrame(
      MaxStreamsFrame(1, /*isBidirectionalIn=*/false));
  EXPECT_EQ(transport->getNumOpenableUnidirectionalStreams(), 1);

  auto result = transport->createUnidirectionalStream();
  EXPECT_TRUE(result);
  EXPECT_EQ(transport->getNumOpenableUnidirectionalStreams(), 0);

  transport->addMaxStreamsFrame(
      MaxStreamsFrame(2, /*isBidirectionalIn=*/false));
}

TEST_F(QuicTransportImplTest, ReadDataAlsoChecksLossAlarm) {
  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();
  auto stream = transport->createBidirectionalStream().value();
  transport->writeChain(stream, folly::IOBuf::copyBuffer("Hey"), true);
  // Artificially stop the write looper so that the read can trigger it.
  transport->writeLooper()->stop();
  transport->addDataToStream(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("Data"), 0));
  EXPECT_TRUE(transport->writeLooper()->isRunning());
  // Drive the event loop once to allow for the write looper to continue.
  evb->loopOnce();
  EXPECT_TRUE(transport->isLossTimeoutScheduled());
  transport.reset();
}

TEST_F(QuicTransportImplTest, ConnectionErrorOnWrite) {
  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();
  auto stream = transport->createBidirectionalStream().value();
  EXPECT_CALL(*socketPtr, write(_, _))
      .WillOnce(SetErrnoAndReturn(ENETUNREACH, -1));
  transport->writeChain(stream, folly::IOBuf::copyBuffer("Hey"), true, nullptr);
  transport->addDataToStream(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("Data"), 0));
  evb->loopOnce();

  EXPECT_TRUE(transport->isClosed());
  EXPECT_EQ(
      transport->getConnectionError(),
      QuicErrorCode(LocalErrorCode::CONNECTION_ABANDONED));
}

TEST_F(QuicTransportImplTest, ReadErrorUnsanitizedErrorMsg) {
  transport->setServerConnectionId();
  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();
  auto stream = transport->createBidirectionalStream().value();
  MockReadCallback rcb;
  transport->setReadCallback(stream, &rcb);
  EXPECT_CALL(rcb, readError(stream, _))
      .Times(1)
      .WillOnce(Invoke([](StreamId, QuicError error) {
        EXPECT_EQ("You need to calm down.", error.message);
      }));

  EXPECT_CALL(*socketPtr, write(_, _)).WillOnce(Invoke([](auto&, auto&) {
    throw std::runtime_error("You need to calm down.");
    return 0;
  }));
  transport->writeChain(
      stream,
      folly::IOBuf::copyBuffer("You are being too loud."),
      true,
      nullptr);
  evb->loopOnce();

  EXPECT_TRUE(transport->isClosed());
}

TEST_F(QuicTransportImplTest, ConnectionErrorUnhandledException) {
  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();
  auto stream = transport->createBidirectionalStream().value();
  EXPECT_CALL(
      connSetupCallback,
      onConnectionSetupError(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::string("Well there's your problem"))));
  EXPECT_CALL(*socketPtr, write(_, _)).WillOnce(Invoke([](auto&, auto&) {
    throw std::runtime_error("Well there's your problem");
    return 0;
  }));
  transport->writeChain(stream, folly::IOBuf::copyBuffer("Hey"), true, nullptr);
  transport->addDataToStream(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("Data"), 0));
  evb->loopOnce();

  EXPECT_TRUE(transport->isClosed());
  EXPECT_EQ(
      transport->getConnectionError(),
      QuicErrorCode(TransportErrorCode::INTERNAL_ERROR));
}

TEST_F(QuicTransportImplTest, LossTimeoutNoLessThanTickInterval) {
  auto tickInterval = evb->timer().getTickInterval();
  transport->scheduleLossTimeout(tickInterval - 1ms);
  EXPECT_NEAR(
      tickInterval.count(),
      transport->getLossTimeoutRemainingTime().count(),
      2);
}

TEST_F(QuicTransportImplTest, CloseStreamAfterReadError) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  transport->transportConn->qLogger = qLogger;
  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  transport->setReadCallback(stream1, &readCb1);

  transport->addStreamReadError(stream1, LocalErrorCode::NO_ERROR);
  transport->closeStream(stream1);

  EXPECT_CALL(readCb1, readError(stream1, IsError(LocalErrorCode::NO_ERROR)));
  transport->driveReadCallbacks();

  EXPECT_FALSE(transport->transportConn->streamManager->streamExists(stream1));
  transport.reset();

  std::vector<int> indices =
      getQLogEventIndices(QLogEventType::TransportStateUpdate, qLogger);
  EXPECT_EQ(indices.size(), 1);
  auto tmp = std::move(qLogger->logs[indices[0]]);
  auto event = dynamic_cast<QLogTransportStateUpdateEvent*>(tmp.get());
  EXPECT_EQ(event->update, getClosingStream("1"));
}

TEST_F(QuicTransportImplTest, CloseStreamAfterReadFin) {
  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb2;
  transport->setReadCallback(stream2, &readCb2);

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0, true));

  EXPECT_CALL(readCb2, readAvailable(stream2)).WillOnce(Invoke([&](StreamId) {
    auto data = transport->read(stream2, 100);
    EXPECT_TRUE(data->second);
    transport->closeStream(stream2);
  }));
  transport->driveReadCallbacks();
  EXPECT_FALSE(transport->transportConn->streamManager->streamExists(stream2));
  transport.reset();
}

TEST_F(QuicTransportImplTest, CloseTransportCleansupOutstandingCounters) {
  transport->transportConn->outstandings
      .packetCount[PacketNumberSpace::Handshake] = 200;
  transport->closeNow(folly::none);
  EXPECT_EQ(
      0,
      transport->transportConn->outstandings
          .packetCount[PacketNumberSpace::Handshake]);
}

TEST_F(QuicTransportImplTest, DeliveryCallbackUnsetAll) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;

  transport->registerDeliveryCallback(stream1, 10, &dcb1);
  transport->registerDeliveryCallback(stream2, 20, &dcb2);

  EXPECT_CALL(dcb1, onCanceled(_, _));
  EXPECT_CALL(dcb2, onCanceled(_, _));

  transport->unsetAllDeliveryCallbacks();

  EXPECT_CALL(dcb1, onCanceled(_, _)).Times(0);
  EXPECT_CALL(dcb2, onCanceled(_, _)).Times(0);

  transport->close(folly::none);
}

TEST_F(QuicTransportImplTest, DeliveryCallbackUnsetOne) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;

  transport->registerDeliveryCallback(stream1, 10, &dcb1);
  transport->registerDeliveryCallback(stream2, 20, &dcb2);

  EXPECT_CALL(dcb1, onCanceled(_, _));
  EXPECT_CALL(dcb2, onCanceled(_, _)).Times(0);

  transport->cancelDeliveryCallbacksForStream(stream1);

  EXPECT_CALL(dcb1, onCanceled(_, _)).Times(0);
  EXPECT_CALL(dcb2, onCanceled(_, _));

  transport->close(folly::none);
}

TEST_F(QuicTransportImplTest, ByteEventCallbacksManagementSingleStream) {
  auto stream = transport->createBidirectionalStream().value();
  uint64_t offset1 = 10, offset2 = 20;

  ByteEvent txEvent1 = {
      .id = stream, .offset = offset1, .type = ByteEvent::Type::TX};
  ByteEvent txEvent2 = {
      .id = stream, .offset = offset2, .type = ByteEvent::Type::TX};
  ByteEvent ackEvent1 = {
      .id = stream, .offset = offset1, .type = ByteEvent::Type::ACK};
  ByteEvent ackEvent2 = {
      .id = stream, .offset = offset2, .type = ByteEvent::Type::ACK};

  // Register 2 TX and 2 ACK events for the same stream at 2 different offsets
  transport->registerTxCallback(
      txEvent1.id, txEvent1.offset, &byteEventCallback);
  transport->registerTxCallback(
      txEvent2.id, txEvent2.offset, &byteEventCallback);
  transport->registerByteEventCallback(
      ByteEvent::Type::ACK, ackEvent1.id, ackEvent1.offset, &byteEventCallback);
  transport->registerByteEventCallback(
      ByteEvent::Type::ACK, ackEvent2.id, ackEvent2.offset, &byteEventCallback);
  EXPECT_THAT(
      byteEventCallback.getByteEventTracker(),
      UnorderedElementsAre(
          getByteEventTrackerMatcher(
              txEvent1, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              txEvent2, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              ackEvent1, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              ackEvent2, TestByteEventCallback::Status::REGISTERED)));

  // Registering the same events a second time will result in an error.
  // as double registrations are not allowed.
  folly::Expected<folly::Unit, LocalErrorCode> ret;
  ret = transport->registerTxCallback(
      txEvent1.id, txEvent1.offset, &byteEventCallback);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());
  ret = transport->registerTxCallback(
      txEvent2.id, txEvent2.offset, &byteEventCallback);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());
  ret = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, ackEvent1.id, ackEvent1.offset, &byteEventCallback);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());
  ret = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, ackEvent2.id, ackEvent2.offset, &byteEventCallback);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());
  EXPECT_THAT(
      byteEventCallback.getByteEventTracker(),
      UnorderedElementsAre(
          getByteEventTrackerMatcher(
              txEvent1, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              txEvent2, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              ackEvent1, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              ackEvent2, TestByteEventCallback::Status::REGISTERED)));

  // On the ACK events, the transport usually sets the srtt value. This value
  // should have NO EFFECT on the ByteEvent's hash and we still should be able
  // to identify the previously registered byte event correctly.
  ackEvent1.srtt = std::chrono::microseconds(1000);
  ackEvent2.srtt = std::chrono::microseconds(2000);

  // Deliver 1 TX and 1 ACK event. Cancel the other TX anc ACK event
  byteEventCallback.onByteEvent(txEvent1);
  byteEventCallback.onByteEvent(ackEvent2);
  byteEventCallback.onByteEventCanceled(txEvent2);
  byteEventCallback.onByteEventCanceled((ByteEventCancellation)ackEvent1);

  EXPECT_THAT(
      byteEventCallback.getByteEventTracker(),
      UnorderedElementsAre(
          getByteEventTrackerMatcher(
              txEvent1, TestByteEventCallback::Status::RECEIVED),
          getByteEventTrackerMatcher(
              txEvent2, TestByteEventCallback::Status::CANCELLED),
          getByteEventTrackerMatcher(
              ackEvent1, TestByteEventCallback::Status::CANCELLED),
          getByteEventTrackerMatcher(
              ackEvent2, TestByteEventCallback::Status::RECEIVED)));
}

TEST_F(QuicTransportImplTest, ByteEventCallbacksManagementDifferentStreams) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  ByteEvent txEvent1 = {
      .id = stream1, .offset = 10, .type = ByteEvent::Type::TX};
  ByteEvent txEvent2 = {
      .id = stream2, .offset = 20, .type = ByteEvent::Type::TX};
  ByteEvent ackEvent1 = {
      .id = stream1, .offset = 10, .type = ByteEvent::Type::ACK};
  ByteEvent ackEvent2 = {
      .id = stream2, .offset = 20, .type = ByteEvent::Type::ACK};

  EXPECT_THAT(byteEventCallback.getByteEventTracker(), IsEmpty());
  // Register 2 TX and 2 ACK events for 2 separate streams.
  transport->registerTxCallback(
      txEvent1.id, txEvent1.offset, &byteEventCallback);
  transport->registerTxCallback(
      txEvent2.id, txEvent2.offset, &byteEventCallback);
  transport->registerByteEventCallback(
      ByteEvent::Type::ACK, ackEvent1.id, ackEvent1.offset, &byteEventCallback);
  transport->registerByteEventCallback(
      ByteEvent::Type::ACK, ackEvent2.id, ackEvent2.offset, &byteEventCallback);
  EXPECT_THAT(
      byteEventCallback.getByteEventTracker(),
      UnorderedElementsAre(
          getByteEventTrackerMatcher(
              txEvent1, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              txEvent2, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              ackEvent1, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              ackEvent2, TestByteEventCallback::Status::REGISTERED)));

  // On the ACK events, the transport usually sets the srtt value. This value
  // should have NO EFFECT on the ByteEvent's hash and we should still be able
  // to identify the previously registered byte event correctly.
  ackEvent1.srtt = std::chrono::microseconds(1000);
  ackEvent2.srtt = std::chrono::microseconds(2000);

  // Deliver the TX event for stream 1 and cancel the ACK event for stream 2
  byteEventCallback.onByteEvent(txEvent1);
  byteEventCallback.onByteEventCanceled((ByteEventCancellation)ackEvent2);

  EXPECT_THAT(
      byteEventCallback.getByteEventTracker(),
      UnorderedElementsAre(
          getByteEventTrackerMatcher(
              txEvent1, TestByteEventCallback::Status::RECEIVED),
          getByteEventTrackerMatcher(
              txEvent2, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              ackEvent1, TestByteEventCallback::Status::REGISTERED),
          getByteEventTrackerMatcher(
              ackEvent2, TestByteEventCallback::Status::CANCELLED)));

  // Deliver the TX event for stream 2 and cancel the ACK event for stream 1
  byteEventCallback.onByteEvent(txEvent2);
  byteEventCallback.onByteEventCanceled((ByteEventCancellation)ackEvent1);

  EXPECT_THAT(
      byteEventCallback.getByteEventTracker(),
      UnorderedElementsAre(
          getByteEventTrackerMatcher(
              txEvent1, TestByteEventCallback::Status::RECEIVED),
          getByteEventTrackerMatcher(
              txEvent2, TestByteEventCallback::Status::RECEIVED),
          getByteEventTrackerMatcher(
              ackEvent1, TestByteEventCallback::Status::CANCELLED),
          getByteEventTrackerMatcher(
              ackEvent2, TestByteEventCallback::Status::CANCELLED)));
}

TEST_F(QuicTransportImplTest, RegisterTxDeliveryCallbackLowerThanExpected) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;
  StrictMock<MockByteEventCallback> txcb3;
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;
  NiceMock<MockDeliveryCallback> dcb3;

  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream, 10)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream, 20)));
  transport->registerTxCallback(stream, 10, &txcb1);
  transport->registerTxCallback(stream, 20, &txcb2);
  transport->registerDeliveryCallback(stream, 10, &dcb1);
  transport->registerDeliveryCallback(stream, 20, &dcb2);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  auto streamState = transport->transportConn->streamManager->getStream(stream);
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  EXPECT_CALL(txcb3, onByteEventRegistered(getTxMatcher(stream, 2)));
  EXPECT_CALL(txcb3, onByteEvent(getTxMatcher(stream, 2)));
  EXPECT_CALL(dcb3, onDeliveryAck(stream, 2, _));
  transport->registerTxCallback(stream, 2, &txcb3);
  transport->registerDeliveryCallback(stream, 2, &dcb3);
  evb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb3);
  Mock::VerifyAndClearExpectations(&dcb3);

  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream, 10)));
  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream, 20)));
  EXPECT_CALL(dcb1, onCanceled(_, _));
  EXPECT_CALL(dcb2, onCanceled(_, _));
  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&txcb3);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);
  Mock::VerifyAndClearExpectations(&dcb3);
}

TEST_F(
    QuicTransportImplTest,
    RegisterTxDeliveryCallbackLowerThanExpectedClose) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb;
  NiceMock<MockDeliveryCallback> dcb;
  auto streamState = transport->transportConn->streamManager->getStream(stream);
  streamState->currentWriteOffset = 7;

  EXPECT_CALL(txcb, onByteEventRegistered(getTxMatcher(stream, 2)));
  EXPECT_CALL(txcb, onByteEventCanceled(getTxMatcher(stream, 2)));
  EXPECT_CALL(dcb, onCanceled(_, _));
  transport->registerTxCallback(stream, 2, &txcb);
  transport->registerDeliveryCallback(stream, 2, &dcb);
  transport->close(folly::none);
  evb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb);
  Mock::VerifyAndClearExpectations(&dcb);
}

TEST_F(QuicTransportImplTest, RegisterDeliveryCallbackMultipleRegistrationsTx) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamState = transport->transportConn->streamManager->getStream(stream);
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Have 2 different recipients register for a callback on the same stream ID
  // and offset that is before the curernt write offset, they will both be
  // scheduled for immediate delivery.
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream, 3)));
  transport->registerTxCallback(stream, 3, &txcb1);
  transport->registerTxCallback(stream, 3, &txcb2);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  // Now, re-register the same callbacks, it should not go through.
  auto ret = transport->registerTxCallback(stream, 3, &txcb1);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());
  ret = transport->registerTxCallback(stream, 3, &txcb2);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());

  // Deliver the first set of registrations.
  EXPECT_CALL(txcb1, onByteEvent(getTxMatcher(stream, 3))).Times(1);
  EXPECT_CALL(txcb2, onByteEvent(getTxMatcher(stream, 3))).Times(1);
  evb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_F(
    QuicTransportImplTest,
    RegisterDeliveryCallbackMultipleRegistrationsAck) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamState = transport->transportConn->streamManager->getStream(stream);
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Have 2 different recipients register for a callback on the same stream ID
  // and offset that is before the curernt write offset, they will both be
  // scheduled for immediate delivery.
  EXPECT_CALL(txcb1, onByteEventRegistered(getAckMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getAckMatcher(stream, 3)));
  transport->registerByteEventCallback(ByteEvent::Type::ACK, stream, 3, &txcb1);
  transport->registerByteEventCallback(ByteEvent::Type::ACK, stream, 3, &txcb2);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  // Now, re-register the same callbacks, it should not go through.
  auto ret = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, stream, 3, &txcb1);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());
  ret = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, stream, 3, &txcb2);
  EXPECT_EQ(LocalErrorCode::INVALID_OPERATION, ret.error());

  // Deliver the first set of registrations.
  EXPECT_CALL(txcb1, onByteEvent(getAckMatcher(stream, 3))).Times(1);
  EXPECT_CALL(txcb2, onByteEvent(getAckMatcher(stream, 3))).Times(1);
  evb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_F(QuicTransportImplTest, RegisterDeliveryCallbackMultipleRecipientsTx) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamState = transport->transportConn->streamManager->getStream(stream);
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Have 2 different recipients register for a callback on the same stream ID
  // and offset.
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream, 3)));
  transport->registerTxCallback(stream, 3, &txcb1);
  transport->registerTxCallback(stream, 3, &txcb2);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  // Now, *before* the runOnEvbAsync gets a chance to run, simulate the
  // delivery of the callback for txcb1 (offset = 3) by deleting it from the
  // outstanding callback queue for this stream ID. This is similar to what
  // happens in processCallbacksAfterNetworkData.
  bool deleted = transport->deleteRegisteredByteEvent(
      stream, 3, &txcb1, ByteEvent::Type::TX);
  CHECK_EQ(true, deleted);

  // Only the callback for txcb2 should be outstanding now. Run the loop to
  // confirm.
  EXPECT_CALL(txcb1, onByteEvent(getTxMatcher(stream, 3))).Times(0);
  EXPECT_CALL(txcb2, onByteEvent(getTxMatcher(stream, 3))).Times(1);
  evb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_F(QuicTransportImplTest, RegisterDeliveryCallbackMultipleRecipientsAck) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamState = transport->transportConn->streamManager->getStream(stream);
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Have 2 different recipients register for a callback on the same stream ID
  // and offset.
  EXPECT_CALL(txcb1, onByteEventRegistered(getAckMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getAckMatcher(stream, 3)));
  transport->registerByteEventCallback(ByteEvent::Type::ACK, stream, 3, &txcb1);
  transport->registerByteEventCallback(ByteEvent::Type::ACK, stream, 3, &txcb2);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  // Now, *before* the runOnEvbAsync gets a chance to run, simulate the
  // delivery of the callback for txcb1 (offset = 3) by deleting it from the
  // outstanding callback queue for this stream ID. This is similar to what
  // happens in processCallbacksAfterNetworkData.
  bool deleted = transport->deleteRegisteredByteEvent(
      stream, 3, &txcb1, ByteEvent::Type::ACK);
  CHECK_EQ(true, deleted);

  // Only the callback for txcb2 should be outstanding now. Run the loop to
  // confirm.
  EXPECT_CALL(txcb1, onByteEvent(getAckMatcher(stream, 3))).Times(0);
  EXPECT_CALL(txcb2, onByteEvent(getAckMatcher(stream, 3))).Times(1);
  evb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_F(QuicTransportImplTest, RegisterDeliveryCallbackAsyncDeliveryTx) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamState = transport->transportConn->streamManager->getStream(stream);
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Register tx callbacks for the same stream at offsets 3 (before current
  // write offset) and 10 (after current write offset).
  // txcb1 (offset = 3) will be scheduled in the lambda (runOnEvbAsync)
  // for immediate delivery. txcb2 (offset = 10) will be queued for delivery
  // when the actual TX for this offset occurs in the future.
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream, 10)));
  transport->registerTxCallback(stream, 3, &txcb1);
  transport->registerTxCallback(stream, 10, &txcb2);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  // Now, *before* the runOnEvbAsync gets a chance to run, simulate the
  // delivery of the callback for txcb1 (offset = 3) by deleting it from the
  // outstanding callback queue for this stream ID. This is similar to what
  // happens in processCallbacksAfterNetworkData.
  bool deleted = transport->deleteRegisteredByteEvent(
      stream, 3, &txcb1, ByteEvent::Type::TX);
  CHECK_EQ(true, deleted);

  // Only txcb2 (offset = 10) should be outstanding now. Run the loop.
  // txcb1 (offset = 3) should not be delivered now because it is already
  // delivered. txcb2 (offset = 10) should not be delivered because the
  // current write offset (7) is still less than the offset requested (10)
  EXPECT_CALL(txcb1, onByteEvent(getTxMatcher(stream, 3))).Times(0);
  EXPECT_CALL(txcb2, onByteEvent(getTxMatcher(stream, 10))).Times(0);
  evb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream, 10)));
  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_F(QuicTransportImplTest, RegisterDeliveryCallbackAsyncDeliveryAck) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamState = transport->transportConn->streamManager->getStream(stream);
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Register tx callbacks for the same stream at offsets 3 (before current
  // write offset) and 10 (after current write offset).
  // txcb1 (offset = 3) will be scheduled in the lambda (runOnEvbAsync)
  // for immediate delivery. txcb2 (offset = 10) will be queued for delivery
  // when the actual TX for this offset occurs in the future.
  EXPECT_CALL(txcb1, onByteEventRegistered(getAckMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getAckMatcher(stream, 10)));
  transport->registerByteEventCallback(ByteEvent::Type::ACK, stream, 3, &txcb1);
  transport->registerByteEventCallback(
      ByteEvent::Type::ACK, stream, 10, &txcb2);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  // Now, *before* the runOnEvbAsync gets a chance to run, simulate the
  // delivery of the callback for txcb1 (offset = 3) by deleting it from the
  // outstanding callback queue for this stream ID. This is similar to what
  // happens in processCallbacksAfterNetworkData.
  bool deleted = transport->deleteRegisteredByteEvent(
      stream, 3, &txcb1, ByteEvent::Type::ACK);
  CHECK_EQ(true, deleted);

  // Only txcb2 (offset = 10) should be outstanding now. Run the loop.
  // txcb1 (offset = 3) should not be delivered now because it is already
  // delivered. txcb2 (offset = 10) should not be delivered because the
  // current write offset (7) is still less than the offset requested (10)
  EXPECT_CALL(txcb1, onByteEvent(getAckMatcher(stream, 3))).Times(0);
  EXPECT_CALL(txcb2, onByteEvent(getAckMatcher(stream, 10))).Times(0);
  evb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  EXPECT_CALL(txcb2, onByteEventCanceled(getAckMatcher(stream, 10)));
  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_F(QuicTransportImplTest, CancelAllByteEventCallbacks) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  NiceMock<MockByteEventCallback> txcb1;
  NiceMock<MockByteEventCallback> txcb2;
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 20)));
  transport->registerTxCallback(stream1, 10, &txcb1);
  transport->registerTxCallback(stream2, 20, &txcb2);

  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;
  transport->registerDeliveryCallback(stream1, 10, &dcb1);
  transport->registerDeliveryCallback(stream2, 20, &dcb2);

  EXPECT_EQ(2, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(2, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      1,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      1,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      1,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      1,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream2, 20)));
  EXPECT_CALL(dcb1, onCanceled(_, _));
  EXPECT_CALL(dcb2, onCanceled(_, _));

  transport->cancelAllByteEventCallbacks();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);

  EXPECT_EQ(0, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(0, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(txcb1, onByteEventCanceled(_)).Times(0);
  EXPECT_CALL(txcb2, onByteEventCanceled(_)).Times(0);
  EXPECT_CALL(dcb1, onCanceled(_, _)).Times(0);
  EXPECT_CALL(dcb2, onCanceled(_, _)).Times(0);

  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);
}

TEST_F(QuicTransportImplTest, CancelByteEventCallbacksForStream) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;

  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 20)));
  transport->registerTxCallback(stream1, 10, &txcb1);
  transport->registerTxCallback(stream2, 20, &txcb2);
  transport->registerDeliveryCallback(stream1, 10, &dcb1);
  transport->registerDeliveryCallback(stream2, 20, &dcb2);

  EXPECT_EQ(2, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(2, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      1,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      1,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      1,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      1,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb2, onByteEventCanceled(_)).Times(0);
  EXPECT_CALL(dcb1, onCanceled(stream1, 10));
  EXPECT_CALL(dcb2, onCanceled(_, _)).Times(0);

  transport->cancelByteEventCallbacksForStream(stream1);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);

  EXPECT_EQ(0, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(2, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      1,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      1,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(txcb1, onByteEventCanceled(_)).Times(0);
  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream2, 20)));
  EXPECT_CALL(dcb1, onCanceled(stream1, _)).Times(0);
  EXPECT_CALL(dcb2, onCanceled(_, 20));

  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);
}

TEST_F(QuicTransportImplTest, CancelByteEventCallbacksForStreamWithOffset) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;

  EXPECT_EQ(0, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(0, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 15)));
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 20)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 10)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 15)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 20)));
  transport->registerTxCallback(stream1, 10, &txcb1);
  transport->registerTxCallback(stream1, 15, &txcb1);
  transport->registerTxCallback(stream1, 20, &txcb1);
  transport->registerTxCallback(stream2, 10, &txcb2);
  transport->registerTxCallback(stream2, 15, &txcb2);
  transport->registerTxCallback(stream2, 20, &txcb2);

  EXPECT_EQ(3, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(3, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      3,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      3,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  transport->registerDeliveryCallback(stream1, 10, &dcb1);
  transport->registerDeliveryCallback(stream1, 15, &dcb1);
  transport->registerDeliveryCallback(stream1, 20, &dcb1);
  transport->registerDeliveryCallback(stream2, 10, &dcb2);
  transport->registerDeliveryCallback(stream2, 15, &dcb2);
  transport->registerDeliveryCallback(stream2, 20, &dcb2);

  EXPECT_EQ(6, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(6, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      3,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      3,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      3,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      3,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream1, 10)));
  EXPECT_CALL(dcb1, onCanceled(stream1, 10));

  // cancels if offset is < (not <=) offset provided
  transport->cancelByteEventCallbacksForStream(stream1, 15);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);

  EXPECT_EQ(4, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(6, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      3,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      3,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream1, 15)));
  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream1, 20)));
  EXPECT_CALL(dcb1, onCanceled(stream1, 15));
  EXPECT_CALL(dcb1, onCanceled(stream1, 20));

  // cancels if offset is < (not <=) offset provided
  transport->cancelByteEventCallbacksForStream(stream1, 21);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);

  EXPECT_EQ(0, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(6, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      3,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      3,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream2, 10)));
  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream2, 15)));
  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream2, 20)));
  EXPECT_CALL(dcb2, onCanceled(stream2, 10));
  EXPECT_CALL(dcb2, onCanceled(stream2, 15));
  EXPECT_CALL(dcb2, onCanceled(stream2, 20));

  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);

  EXPECT_EQ(0, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(0, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));
}

TEST_F(QuicTransportImplTest, CancelByteEventCallbacksTx) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;

  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 15)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 10)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 15)));
  transport->registerTxCallback(stream1, 10, &txcb1);
  transport->registerTxCallback(stream1, 15, &txcb1);
  transport->registerTxCallback(stream2, 10, &txcb2);
  transport->registerTxCallback(stream2, 15, &txcb2);
  transport->registerDeliveryCallback(stream1, 10, &dcb1);
  transport->registerDeliveryCallback(stream1, 15, &dcb1);
  transport->registerDeliveryCallback(stream2, 10, &dcb2);
  transport->registerDeliveryCallback(stream2, 15, &dcb2);

  EXPECT_EQ(4, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(4, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream1, 15)));
  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream2, 10)));
  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream2, 15)));

  transport->cancelByteEventCallbacks(ByteEvent::Type::TX);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);

  EXPECT_EQ(2, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(2, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(dcb1, onCanceled(stream1, 10));
  EXPECT_CALL(dcb1, onCanceled(stream1, 15));
  EXPECT_CALL(dcb2, onCanceled(stream2, 10));
  EXPECT_CALL(dcb2, onCanceled(stream2, 15));

  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);
}

TEST_F(QuicTransportImplTest, CancelByteEventCallbacksDelivery) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;

  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 15)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 10)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 15)));
  transport->registerTxCallback(stream1, 10, &txcb1);
  transport->registerTxCallback(stream1, 15, &txcb1);
  transport->registerTxCallback(stream2, 10, &txcb2);
  transport->registerTxCallback(stream2, 15, &txcb2);
  transport->registerDeliveryCallback(stream1, 10, &dcb1);
  transport->registerDeliveryCallback(stream1, 15, &dcb1);
  transport->registerDeliveryCallback(stream2, 10, &dcb2);
  transport->registerDeliveryCallback(stream2, 15, &dcb2);

  EXPECT_EQ(4, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(4, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(dcb1, onCanceled(stream1, 10));
  EXPECT_CALL(dcb1, onCanceled(stream1, 15));
  EXPECT_CALL(dcb2, onCanceled(stream2, 10));
  EXPECT_CALL(dcb2, onCanceled(stream2, 15));

  transport->cancelByteEventCallbacks(ByteEvent::Type::ACK);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);

  EXPECT_EQ(2, transport->getNumByteEventCallbacksForStream(stream1));
  EXPECT_EQ(2, transport->getNumByteEventCallbacksForStream(stream2));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream1));
  EXPECT_EQ(
      2,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::TX, stream2));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream1));
  EXPECT_EQ(
      0,
      transport->getNumByteEventCallbacksForStream(
          ByteEvent::Type::ACK, stream2));

  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream1, 15)));
  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream2, 10)));
  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream2, 15)));

  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);
}

TEST_F(QuicTransportImplTest, TestNotifyPendingConnWriteOnCloseWithoutError) {
  NiceMock<MockWriteCallback> wcb;
  EXPECT_CALL(
      wcb,
      onConnectionWriteError(IsError(GenericApplicationErrorCode::NO_ERROR)));
  transport->notifyPendingWriteOnConnection(&wcb);
  transport->close(folly::none);
  evb->loopOnce();
}

TEST_P(QuicTransportImplTestClose, TestNotifyPendingConnWriteOnCloseWithError) {
  NiceMock<MockWriteCallback> wcb;
  transport->notifyPendingWriteOnConnection(&wcb);
  if (GetParam()) {
    EXPECT_CALL(
        wcb,
        onConnectionWriteError(
            IsAppError(GenericApplicationErrorCode::UNKNOWN)));
    transport->close(QuicError(
        QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
        std::string("Bye")));
  } else {
    transport->close(folly::none);
  }
  evb->loopOnce();
}

TEST_F(QuicTransportImplTest, TestNotifyPendingWriteWithActiveCallback) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  EXPECT_CALL(wcb, onStreamWriteReady(stream, _));
  auto ok1 = transport->notifyPendingWriteOnStream(stream, &wcb);
  EXPECT_TRUE(ok1.hasValue());
  auto ok2 = transport->notifyPendingWriteOnStream(stream, &wcb);
  EXPECT_EQ(ok2.error(), quic::LocalErrorCode::CALLBACK_ALREADY_INSTALLED);
  evb->loopOnce();
}

TEST_F(QuicTransportImplTest, TestNotifyPendingWriteOnCloseWithoutError) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  EXPECT_CALL(
      wcb,
      onStreamWriteError(
          stream, IsError(GenericApplicationErrorCode::NO_ERROR)));
  transport->notifyPendingWriteOnStream(stream, &wcb);
  transport->close(folly::none);
  evb->loopOnce();
}

TEST_P(QuicTransportImplTestClose, TestNotifyPendingWriteOnCloseWithError) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  transport->notifyPendingWriteOnStream(stream, &wcb);
  if (GetParam()) {
    EXPECT_CALL(
        wcb,
        onStreamWriteError(
            stream, IsAppError(GenericApplicationErrorCode::UNKNOWN)));
    transport->close(QuicError(
        QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
        std::string("Bye")));
  } else {
    transport->close(folly::none);
  }
  evb->loopOnce();
}

TEST_F(QuicTransportImplTest, TestTransportCloseWithMaxPacketNumber) {
  transport->setServerConnectionId();
  transport->transportConn->pendingEvents.closeTransport = false;
  EXPECT_NO_THROW(transport->invokeWriteSocketData());

  transport->transportConn->pendingEvents.closeTransport = true;
  EXPECT_THROW(transport->invokeWriteSocketData(), QuicTransportException);
}

TEST_F(QuicTransportImplTest, TestGracefulCloseWithActiveStream) {
  EXPECT_CALL(connCallback, onConnectionEnd()).Times(0);
  EXPECT_CALL(connCallback, onConnectionError(_)).Times(0);

  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  NiceMock<MockWriteCallback> wcbConn;
  NiceMock<MockReadCallback> rcb;
  StrictMock<MockByteEventCallback> txCb;
  StrictMock<MockDeliveryCallback> deliveryCb;
  EXPECT_CALL(
      wcb, onStreamWriteError(stream, IsError(LocalErrorCode::NO_ERROR)));
  EXPECT_CALL(
      wcbConn, onConnectionWriteError(IsError(LocalErrorCode::NO_ERROR)));
  EXPECT_CALL(rcb, readError(stream, IsError(LocalErrorCode::NO_ERROR)));
  EXPECT_CALL(deliveryCb, onCanceled(stream, _));
  EXPECT_CALL(txCb, onByteEventCanceled(getTxMatcher(stream, 0)));
  EXPECT_CALL(txCb, onByteEventCanceled(getTxMatcher(stream, 4)));

  transport->notifyPendingWriteOnConnection(&wcbConn);
  transport->notifyPendingWriteOnStream(stream, &wcb);
  transport->setReadCallback(stream, &rcb);
  EXPECT_CALL(*socketPtr, write(_, _))
      .WillRepeatedly(SetErrnoAndReturn(EAGAIN, -1));
  transport->writeChain(stream, IOBuf::copyBuffer("hello"), true, &deliveryCb);
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 0)));
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 4)));
  EXPECT_FALSE(transport->registerTxCallback(stream, 0, &txCb).hasError());
  EXPECT_FALSE(transport->registerTxCallback(stream, 4, &txCb).hasError());
  transport->closeGracefully();

  ASSERT_FALSE(transport->transportClosed);
  EXPECT_FALSE(transport->createBidirectionalStream());

  EXPECT_TRUE(transport->setReadCallback(stream, &rcb).hasError());
  EXPECT_TRUE(transport->notifyPendingWriteOnStream(stream, &wcb).hasError());
  EXPECT_TRUE(transport->notifyPendingWriteOnConnection(&wcbConn).hasError());
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 2))).Times(0);
  EXPECT_TRUE(transport->registerTxCallback(stream, 2, &txCb).hasError());
  EXPECT_TRUE(
      transport->registerDeliveryCallback(stream, 2, &deliveryCb).hasError());
  EXPECT_TRUE(
      transport->resetStream(stream, GenericApplicationErrorCode::UNKNOWN)
          .hasError());

  transport->addDataToStream(
      stream, StreamBuffer(IOBuf::copyBuffer("hello"), 0, false));
  EXPECT_FALSE(transport->transportConn->streamManager->getStream(stream)
                   ->readBuffer.empty());

  // Close the last stream.
  // TODO: replace this when we call conn callbacks.
  // EXPECT_CALL(connCallback, onConnectionEnd());
  transport->closeStream(stream);
  ASSERT_TRUE(transport->transportClosed);

  evb->loopOnce();
}

TEST_F(QuicTransportImplTest, TestGracefulCloseWithNoActiveStream) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  NiceMock<MockWriteCallback> wcbConn;
  NiceMock<MockReadCallback> rcb;
  NiceMock<MockDeliveryCallback> deliveryCb;
  NiceMock<MockByteEventCallback> txCb;
  EXPECT_CALL(
      rcb, readError(stream, IsError(GenericApplicationErrorCode::NO_ERROR)));
  EXPECT_CALL(deliveryCb, onDeliveryAck(stream, _, _));
  EXPECT_CALL(txCb, onByteEvent(getTxMatcher(stream, 0)));
  EXPECT_CALL(txCb, onByteEvent(getTxMatcher(stream, 4)));

  EXPECT_CALL(connCallback, onConnectionEnd()).Times(0);
  EXPECT_CALL(connCallback, onConnectionError(_)).Times(0);

  transport->setReadCallback(stream, &rcb);
  EXPECT_CALL(*socketPtr, write(_, _))
      .WillRepeatedly(SetErrnoAndReturn(EAGAIN, -1));
  transport->writeChain(stream, IOBuf::copyBuffer("hello"), true, &deliveryCb);
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 0)));
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 4)));
  EXPECT_FALSE(transport->registerTxCallback(stream, 0, &txCb).hasError());
  EXPECT_FALSE(transport->registerTxCallback(stream, 4, &txCb).hasError());

  // Close the last stream.
  auto streamState = transport->transportConn->streamManager->getStream(stream);
  // Fake that the data was TXed and delivered to keep all the state
  // consistent.
  streamState->currentWriteOffset = 7;
  transport->transportConn->streamManager->addTx(stream);
  transport->transportConn->streamManager->addDeliverable(stream);
  transport->closeStream(stream);
  transport->close(folly::none);

  ASSERT_TRUE(transport->transportClosed);
  EXPECT_FALSE(transport->createBidirectionalStream());

  EXPECT_TRUE(transport->setReadCallback(stream, &rcb).hasError());
  EXPECT_TRUE(transport->notifyPendingWriteOnStream(stream, &wcb).hasError());
  EXPECT_TRUE(transport->notifyPendingWriteOnConnection(&wcbConn).hasError());
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 2))).Times(0);
  EXPECT_TRUE(transport->registerTxCallback(stream, 2, &txCb).hasError());
  EXPECT_TRUE(
      transport->registerDeliveryCallback(stream, 2, &deliveryCb).hasError());
  EXPECT_TRUE(
      transport->resetStream(stream, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
}

TEST_F(QuicTransportImplTest, TestImmediateClose) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  NiceMock<MockWriteCallback> wcbConn;
  NiceMock<MockReadCallback> rcb;
  NiceMock<MockPeekCallback> pcb;
  NiceMock<MockDeliveryCallback> deliveryCb;
  NiceMock<MockByteEventCallback> txCb;
  EXPECT_CALL(
      wcb,
      onStreamWriteError(
          stream, IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  EXPECT_CALL(
      wcbConn,
      onConnectionWriteError(IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  EXPECT_CALL(
      rcb, readError(stream, IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  EXPECT_CALL(
      pcb, peekError(stream, IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  EXPECT_CALL(deliveryCb, onCanceled(stream, _));
  EXPECT_CALL(txCb, onByteEventCanceled(getTxMatcher(stream, 0)));
  EXPECT_CALL(txCb, onByteEventCanceled(getTxMatcher(stream, 4)));

  EXPECT_CALL(connCallback, onConnectionError(_)).Times(0);

  transport->notifyPendingWriteOnConnection(&wcbConn);
  transport->notifyPendingWriteOnStream(stream, &wcb);
  transport->setReadCallback(stream, &rcb);
  transport->setPeekCallback(stream, &pcb);
  EXPECT_CALL(*socketPtr, write(_, _))
      .WillRepeatedly(SetErrnoAndReturn(EAGAIN, -1));
  transport->writeChain(stream, IOBuf::copyBuffer("hello"), true, &deliveryCb);
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 0)));
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 4)));
  EXPECT_FALSE(transport->registerTxCallback(stream, 0, &txCb).hasError());
  EXPECT_FALSE(transport->registerTxCallback(stream, 4, &txCb).hasError());
  transport->close(QuicError(
      QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
      std::string("Error")));

  ASSERT_TRUE(transport->transportClosed);
  EXPECT_FALSE(transport->createBidirectionalStream());

  EXPECT_TRUE(transport->setReadCallback(stream, &rcb).hasError());
  EXPECT_TRUE(transport->notifyPendingWriteOnStream(stream, &wcb).hasError());
  EXPECT_TRUE(transport->notifyPendingWriteOnConnection(&wcbConn).hasError());
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 2))).Times(0);
  EXPECT_TRUE(transport->registerTxCallback(stream, 2, &txCb).hasError());
  EXPECT_TRUE(
      transport->registerDeliveryCallback(stream, 2, &deliveryCb).hasError());
  EXPECT_TRUE(
      transport->resetStream(stream, GenericApplicationErrorCode::UNKNOWN)
          .hasError());

  transport->addDataToStream(
      stream, StreamBuffer(IOBuf::copyBuffer("hello"), 0, false));
  EXPECT_EQ(
      transport->transportConn->streamManager->getStream(stream), nullptr);
  evb->loopOnce();
}

TEST_F(QuicTransportImplTest, ResetStreamUnsetWriteCallback) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  EXPECT_CALL(wcb, onStreamWriteError(stream, _)).Times(0);
  transport->notifyPendingWriteOnStream(stream, &wcb);
  EXPECT_FALSE(
      transport->resetStream(stream, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
  evb->loopOnce();
}

TEST_F(QuicTransportImplTest, ResetAllNonControlStreams) {
  auto stream1 = transport->createBidirectionalStream().value();
  ASSERT_FALSE(transport->setControlStream(stream1));
  NiceMock<MockWriteCallback> wcb1;
  NiceMock<MockReadCallback> rcb1;
  EXPECT_CALL(wcb1, onStreamWriteError(stream1, _)).Times(0);
  EXPECT_CALL(rcb1, readError(stream1, _)).Times(0);
  transport->notifyPendingWriteOnStream(stream1, &wcb1);
  transport->setReadCallback(stream1, &rcb1);

  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb2;
  NiceMock<MockReadCallback> rcb2;
  EXPECT_CALL(wcb2, onStreamWriteError(stream2, _)).Times(1);
  EXPECT_CALL(rcb2, readError(stream2, _)).Times(1);
  transport->notifyPendingWriteOnStream(stream2, &wcb2);
  transport->setReadCallback(stream2, &rcb2);

  auto stream3 = transport->createUnidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb3;
  transport->notifyPendingWriteOnStream(stream3, &wcb3);
  EXPECT_CALL(wcb3, onStreamWriteError(stream3, _)).Times(1);

  auto stream4 = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb4;
  NiceMock<MockReadCallback> rcb4;
  EXPECT_CALL(wcb4, onStreamWriteError(stream4, _))
      .WillOnce(Invoke(
          [&](auto, auto) { transport->setReadCallback(stream4, nullptr); }));
  EXPECT_CALL(rcb4, readError(_, _)).Times(0);
  transport->notifyPendingWriteOnStream(stream4, &wcb4);
  transport->setReadCallback(stream4, &rcb4);

  transport->resetNonControlStreams(
      GenericApplicationErrorCode::UNKNOWN, "bye bye");
  evb->loopOnce();

  // Have to manually unset the read callbacks so they aren't use-after-freed.
  transport->unsetAllReadCallbacks();
}

TEST_F(QuicTransportImplTest, DestroyWithoutClosing) {
  EXPECT_CALL(connCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(connCallback, onConnectionEnd()).Times(0);
  transport.reset();
}

TEST_F(QuicTransportImplTest, UncleanShutdownEventBase) {
  // if abruptly shutting down the eventbase we should avoid scheduling
  // any new timer.
  transport->setIdleTimeout();
  evb.reset();
}

TEST_F(QuicTransportImplTest, GetLocalAddressBoundSocket) {
  SocketAddress addr("127.0.0.1", 443);
  EXPECT_CALL(*socketPtr, isBound()).WillOnce(Return(true));
  EXPECT_CALL(*socketPtr, address()).WillRepeatedly(ReturnRef(addr));
  SocketAddress localAddr = transport->getLocalAddress();
  EXPECT_TRUE(localAddr == addr);
}

TEST_F(QuicTransportImplTest, GetLocalAddressUnboundSocket) {
  EXPECT_CALL(*socketPtr, isBound()).WillOnce(Return(false));
  SocketAddress localAddr = transport->getLocalAddress();
  EXPECT_FALSE(localAddr.isInitialized());
}

TEST_F(QuicTransportImplTest, GetLocalAddressBadSocket) {
  auto badTransport = std::make_shared<TestQuicTransport>(
      evb.get(), nullptr, &connSetupCallback, &connCallback);
  badTransport->closeWithoutWrite();
  SocketAddress localAddr = badTransport->getLocalAddress();
  EXPECT_FALSE(localAddr.isInitialized());
}

TEST_F(QuicTransportImplTest, AsyncStreamFlowControlWrite) {
  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();
  auto stream = transport->createBidirectionalStream().value();
  auto streamState = transport->transportConn->streamManager->getStream(stream);
  transport->setServerConnectionId();
  transport->writeLooper()->stop();
  streamState->flowControlState.advertisedMaxOffset = 0; // Easier to calculate
  transport->setStreamFlowControlWindow(stream, 4000);
  EXPECT_EQ(0, streamState->flowControlState.advertisedMaxOffset);
  // Loop it:
  EXPECT_TRUE(transport->writeLooper()->isRunning());
  transport->writeLooper()->runLoopCallback();
  EXPECT_EQ(4000, streamState->flowControlState.advertisedMaxOffset);
}

TEST_F(QuicTransportImplTest, ExceptionInWriteLooperDoesNotCrash) {
  auto stream = transport->createBidirectionalStream().value();
  transport->setReadCallback(stream, nullptr);
  transport->writeChain(stream, IOBuf::copyBuffer("hello"), true, nullptr);
  transport->addDataToStream(
      stream, StreamBuffer(IOBuf::copyBuffer("hello"), 0, false));
  EXPECT_CALL(*socketPtr, write(_, _)).WillOnce(SetErrnoAndReturn(EBADF, -1));
  EXPECT_CALL(connSetupCallback, onConnectionSetupError(_))
      .WillOnce(Invoke([&](auto) { transport.reset(); }));
  transport->writeLooper()->runLoopCallback();
}

class QuicTransportImplTestUniBidi : public QuicTransportImplTest,
                                     public testing::WithParamInterface<bool> {
};

quic::StreamId createStream(
    std::shared_ptr<TestQuicTransport> transport,
    bool unidirectional) {
  if (unidirectional) {
    return transport->createUnidirectionalStream().value();
  } else {
    return transport->createBidirectionalStream().value();
  }
}

INSTANTIATE_TEST_SUITE_P(
    QuicTransportImplTest,
    QuicTransportImplTestUniBidi,
    Values(true, false));

TEST_P(QuicTransportImplTestUniBidi, AppIdleTest) {
  auto& conn = transport->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  EXPECT_CALL(*rawCongestionController, setAppIdle(false, _)).Times(0);
  auto stream = createStream(transport, GetParam());

  EXPECT_CALL(*rawCongestionController, setAppIdle(true, _));
  transport->closeStream(stream);
}

TEST_P(QuicTransportImplTestUniBidi, AppIdleTestControlStreams) {
  auto& conn = transport->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  EXPECT_CALL(*rawCongestionController, setAppIdle(false, _)).Times(0);
  auto stream = createStream(transport, GetParam());
  ASSERT_TRUE(stream);

  auto ctrlStream1 = createStream(transport, GetParam());
  ASSERT_TRUE(ctrlStream1);
  transport->setControlStream(ctrlStream1);
  auto ctrlStream2 = createStream(transport, GetParam());
  ASSERT_TRUE(ctrlStream2);
  transport->setControlStream(ctrlStream2);

  EXPECT_CALL(*rawCongestionController, setAppIdle(true, _));
  transport->closeStream(stream);
}

TEST_P(QuicTransportImplTestUniBidi, AppIdleTestOnlyControlStreams) {
  auto& conn = transport->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);

  auto ctrlStream1 = createStream(transport, GetParam());
  EXPECT_CALL(*rawCongestionController, setAppIdle(true, _)).Times(1);
  transport->setControlStream(ctrlStream1);
  EXPECT_CALL(*rawCongestionController, setAppIdle(false, _)).Times(1);
  auto ctrlStream2 = createStream(transport, GetParam());
  EXPECT_CALL(*rawCongestionController, setAppIdle(true, _)).Times(1);
  transport->setControlStream(ctrlStream2);

  EXPECT_CALL(*rawCongestionController, setAppIdle(_, _)).Times(0);
  transport->closeStream(ctrlStream1);
  transport->closeStream(ctrlStream2);
}

TEST_F(QuicTransportImplTest, UnidirectionalInvalidReadFuncs) {
  auto stream = transport->createUnidirectionalStream().value();
  EXPECT_THROW(
      transport->read(stream, 100).thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport->setReadCallback(stream, nullptr).thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport->pauseRead(stream).thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport->resumeRead(stream).thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport->stopSending(stream, GenericApplicationErrorCode::UNKNOWN)
          .thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
}

TEST_F(QuicTransportImplTest, UnidirectionalInvalidWriteFuncs) {
  auto readData = folly::IOBuf::copyBuffer("actual stream data");
  StreamId stream = 0x6;
  transport->addDataToStream(stream, StreamBuffer(readData->clone(), 0, true));
  EXPECT_THROW(
      transport->getStreamWriteOffset(stream).thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport->getStreamWriteBufferedBytes(stream).thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport->notifyPendingWriteOnStream(stream, nullptr)
          .thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport->writeChain(stream, folly::IOBuf::copyBuffer("Hey"), false)
          .thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport->registerDeliveryCallback(stream, 0, nullptr)
          .thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport->registerTxCallback(stream, 0, nullptr).thenOrThrow([&](auto) {
      }),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport
          ->registerByteEventCallback(ByteEvent::Type::ACK, stream, 0, nullptr)
          .thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport
          ->registerByteEventCallback(ByteEvent::Type::TX, stream, 0, nullptr)
          .thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
  EXPECT_THROW(
      transport->resetStream(stream, GenericApplicationErrorCode::UNKNOWN)
          .thenOrThrow([&](auto) {}),
      folly::BadExpectedAccess<LocalErrorCode>);
}

TEST_P(QuicTransportImplTestUniBidi, IsServerStream) {
  auto stream = createStream(transport, GetParam());
  EXPECT_TRUE(transport->isServerStream(stream));
}

TEST_P(QuicTransportImplTestUniBidi, IsClientStream) {
  auto stream = createStream(transport, GetParam());
  EXPECT_FALSE(transport->isClientStream(stream));
}

TEST_F(QuicTransportImplTest, IsUnidirectionalStream) {
  auto stream = transport->createUnidirectionalStream().value();
  EXPECT_TRUE(transport->isUnidirectionalStream(stream));
}

TEST_F(QuicTransportImplTest, IsBidirectionalStream) {
  auto stream = transport->createBidirectionalStream().value();
  EXPECT_TRUE(transport->isBidirectionalStream(stream));
}

TEST_F(QuicTransportImplTest, GetStreamDirectionalityUnidirectional) {
  auto stream = transport->createUnidirectionalStream().value();
  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      transport->getStreamDirectionality(stream));
}

TEST_F(QuicTransportImplTest, GetStreamDirectionalityBidirectional) {
  auto stream = transport->createBidirectionalStream().value();
  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      transport->getStreamDirectionality(stream));
}

TEST_F(QuicTransportImplTest, PeekCallbackDataAvailable) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  NiceMock<MockPeekCallback> peekCb1;
  NiceMock<MockPeekCallback> peekCb2;

  transport->setPeekCallback(stream1, &peekCb1);
  transport->setPeekCallback(stream2, &peekCb2);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10));

  EXPECT_CALL(peekCb1, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(peekCb2, onDataAvailable(stream2, _));
  transport->driveReadCallbacks();

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(peekCb1, onDataAvailable(stream1, _));
  EXPECT_CALL(peekCb2, onDataAvailable(stream2, _));
  transport->driveReadCallbacks();

  transport->setPeekCallback(stream1, nullptr);
  transport->setPeekCallback(stream2, nullptr);
  transport->driveReadCallbacks();

  transport.reset();
}

TEST_F(QuicTransportImplTest, PeekError) {
  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockPeekCallback> peekCb1;
  transport->setPeekCallback(stream1, &peekCb1);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->addStreamReadError(stream1, LocalErrorCode::STREAM_CLOSED);

  EXPECT_CALL(
      peekCb1, peekError(stream1, IsError(LocalErrorCode::STREAM_CLOSED)));

  transport->driveReadCallbacks();

  EXPECT_CALL(peekCb1, peekError(stream1, _));

  transport.reset();
}

TEST_F(QuicTransportImplTest, PeekCallbackUnsetAll) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  NiceMock<MockPeekCallback> peekCb1;
  NiceMock<MockPeekCallback> peekCb2;

  // Set the peek callbacks and add data to the streams, and see that the
  // callbacks do indeed fire

  transport->setPeekCallback(stream1, &peekCb1);
  transport->setPeekCallback(stream2, &peekCb2);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(peekCb1, onDataAvailable(stream1, _));
  EXPECT_CALL(peekCb2, onDataAvailable(stream2, _));

  transport->driveReadCallbacks();

  // unset all of the peek callbacks and see that the callbacks don't fire
  // after data is added to the streams

  transport->unsetAllPeekCallbacks();

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->addDataToStream(
      stream2, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(peekCb1, onDataAvailable(stream1, _)).Times(0);
  EXPECT_CALL(peekCb2, onDataAvailable(stream2, _)).Times(0);

  transport->driveReadCallbacks();
}

TEST_F(QuicTransportImplTest, PeekCallbackChangePeekCallback) {
  InSequence enforceOrder;

  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockPeekCallback> peekCb1;
  NiceMock<MockPeekCallback> peekCb2;

  transport->setPeekCallback(stream1, &peekCb1);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(peekCb1, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  transport->setPeekCallback(stream1, &peekCb2);
  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(peekCb2, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_F(QuicTransportImplTest, PeekCallbackPauseResume) {
  InSequence enforceOrder;

  auto stream1 = transport->createBidirectionalStream().value();
  NiceMock<MockPeekCallback> peekCb1;

  transport->setPeekCallback(stream1, &peekCb1);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  auto res = transport->pausePeek(stream1);
  EXPECT_TRUE(res);
  EXPECT_CALL(peekCb1, onDataAvailable(stream1, _)).Times(0);
  transport->driveReadCallbacks();

  res = transport->resumePeek(stream1);
  EXPECT_TRUE(res);
  EXPECT_CALL(peekCb1, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  auto stream2 = transport->createBidirectionalStream().value();
  res = transport->pausePeek(stream2);
  EXPECT_FALSE(res);
  EXPECT_EQ(LocalErrorCode::APP_ERROR, res.error());
  transport.reset();
}

TEST_F(QuicTransportImplTest, PeekCallbackNoCallbackSet) {
  auto stream1 = transport->createBidirectionalStream().value();

  transport->addDataToStream(
      stream1,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10));
  transport->driveReadCallbacks();
  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_F(QuicTransportImplTest, PeekCallbackInvalidStream) {
  NiceMock<MockPeekCallback> peekCb1;
  StreamId invalidStream = 10;
  EXPECT_TRUE(transport->setPeekCallback(invalidStream, &peekCb1).hasError());
  transport.reset();
}

TEST_F(QuicTransportImplTest, PeekData) {
  InSequence enforceOrder;

  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockPeekCallback> peekCb1;
  auto peekData = folly::IOBuf::copyBuffer("actual stream data");

  transport->setPeekCallback(stream1, &peekCb1);

  EXPECT_CALL(peekCb1, onDataAvailable(stream1, _));
  transport->addDataToStream(stream1, StreamBuffer(peekData->clone(), 0));
  transport->driveReadCallbacks();

  bool cbCalled = false;
  auto peekCallback = [&](StreamId id,
                          const folly::Range<PeekIterator>& range) {
    cbCalled = true;
    EXPECT_EQ(id, stream1);
    EXPECT_EQ(range.size(), 1);
    auto bufClone = range[0].data.front()->clone();
    EXPECT_EQ("actual stream data", bufClone->moveToFbString().toStdString());
  };

  transport->peek(stream1, peekCallback);
  EXPECT_TRUE(cbCalled);
  transport.reset();
}

TEST_F(QuicTransportImplTest, PeekDataWithError) {
  InSequence enforceOrder;

  auto streamId = transport->createBidirectionalStream().value();
  auto peekData = folly::IOBuf::copyBuffer("actual stream data");
  transport->addDataToStream(streamId, StreamBuffer(peekData->clone(), 0));

  bool cbCalled = false;
  auto peekCallback = [&](StreamId, const folly::Range<PeekIterator>&) {
    cbCalled = true;
  };

  // Same local error code should be returned.
  transport->addStreamReadError(streamId, LocalErrorCode::NO_ERROR);
  auto result = transport->peek(streamId, peekCallback);
  EXPECT_FALSE(cbCalled);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::NO_ERROR, result.error());

  // LocalErrorCode::INTERNAL_ERROR should be returned.
  transport->addStreamReadError(
      streamId, TransportErrorCode::FLOW_CONTROL_ERROR);
  result = transport->peek(streamId, peekCallback);
  EXPECT_FALSE(cbCalled);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INTERNAL_ERROR, result.error());

  transport.reset();
}

TEST_F(QuicTransportImplTest, ConsumeDataWithError) {
  InSequence enforceOrder;

  auto streamId = transport->createBidirectionalStream().value();
  auto peekData = folly::IOBuf::copyBuffer("actual stream data");
  transport->addDataToStream(streamId, StreamBuffer(peekData->clone(), 0));

  // Same local error code should be returned.
  transport->addStreamReadError(streamId, LocalErrorCode::NO_ERROR);
  auto result = transport->consume(streamId, 1);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::NO_ERROR, result.error());

  // LocalErrorCode::INTERNAL_ERROR should be returned.
  transport->addStreamReadError(
      streamId, TransportErrorCode::FLOW_CONTROL_ERROR);
  result = transport->consume(streamId, 1);
  EXPECT_TRUE(result.hasError());
  EXPECT_EQ(LocalErrorCode::INTERNAL_ERROR, result.error());

  transport.reset();
}

TEST_F(QuicTransportImplTest, PeekConsumeReadTest) {
  InSequence enforceOrder;

  auto stream1 = transport->createBidirectionalStream().value();
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  NiceMock<MockPeekCallback> peekCb;
  NiceMock<MockReadCallback> readCb;

  transport->setPeekCallback(stream1, &peekCb);
  transport->setReadCallback(stream1, &readCb);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  // Both peek and read should be called.
  EXPECT_CALL(readCb, readAvailable(stream1));
  EXPECT_CALL(peekCb, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  // Only read should be called
  EXPECT_CALL(readCb, readAvailable(stream1));
  transport->driveReadCallbacks();

  // Consume 5 bytes.
  transport->consume(stream1, 5);

  // Both peek and read should be called.
  // Read - because it is called every time
  // Peek - because the peekable range has changed
  EXPECT_CALL(readCb, readAvailable(stream1));
  EXPECT_CALL(peekCb, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  // Read 10 bytes.
  transport->read(stream1, 10).thenOrThrow([&](std::pair<Buf, bool> data) {
    EXPECT_EQ("l stream d", data.first->moveToFbString().toStdString());
  });

  // Both peek and read should be called.
  // Read - because it is called every time
  // Peek - because the peekable range has changed
  EXPECT_CALL(readCb, readAvailable(stream1));
  EXPECT_CALL(peekCb, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  // Only read should be called.
  EXPECT_CALL(readCb, readAvailable(stream1));
  transport->driveReadCallbacks();

  // Consume the rest of the data.
  // Only 3 bytes left, try consuming 42.
  transport->consume(stream1, 42);

  // Neither read nor peek should be called.
  EXPECT_CALL(readCb, readAvailable(stream1)).Times(0);
  EXPECT_CALL(peekCb, onDataAvailable(stream1, _)).Times(0);
  transport->driveReadCallbacks();

  // Add more data, this time with a gap.
  auto buf1 = IOBuf::copyBuffer("I just met you and this is crazy.");
  auto buf2 = IOBuf::copyBuffer(" Here is my number, so call");
  auto buf3 = IOBuf::copyBuffer(" me maybe.");
  transport->addDataToStream(stream1, StreamBuffer(buf1->clone(), 0));
  transport->addDataToStream(
      stream1,
      StreamBuffer(
          buf3->clone(),
          buf1->computeChainDataLength() + buf2->computeChainDataLength()));

  // Both peek and read should be called.
  EXPECT_CALL(readCb, readAvailable(stream1));
  EXPECT_CALL(peekCb, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  // Consume left part.
  transport->consume(stream1, buf1->computeChainDataLength());

  // Only peek should be called.
  EXPECT_CALL(peekCb, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  // Fill in the gap.
  transport->addDataToStream(
      stream1, StreamBuffer(buf2->clone(), buf1->computeChainDataLength()));

  // Both peek and read should be called.
  EXPECT_CALL(readCb, readAvailable(stream1));
  EXPECT_CALL(peekCb, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  // Read the rest of the buffer.
  transport->read(stream1, 0).thenOrThrow([&](std::pair<Buf, bool> data) {
    EXPECT_EQ(
        " Here is my number, so call me maybe.",
        data.first->moveToFbString().toStdString());
  });

  // Neither read nor peek should be called.
  EXPECT_CALL(readCb, readAvailable(stream1)).Times(0);
  EXPECT_CALL(peekCb, onDataAvailable(stream1, _)).Times(0);
  transport->driveReadCallbacks();

  transport.reset();
}

TEST_F(QuicTransportImplTest, UpdatePeekableListNoDataTest) {
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);

  // Insert streamId into the list.
  conn->streamManager->peekableStreams().insert(streamId);
  // After the call the streamId should be removed
  // from the list since there is no peekable data in the stream.
  conn->streamManager->updatePeekableStreams(*stream);
  EXPECT_EQ(0, conn->streamManager->peekableStreams().count(streamId));
}

TEST_F(QuicTransportImplTest, UpdatePeekableListWithDataTest) {
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);

  // Add some data to the stream.
  transport->addDataToStream(
      streamId,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  // streamId is in the list after the above call.
  EXPECT_EQ(1, conn->streamManager->peekableStreams().count(streamId));

  // After the call the streamId shall remain
  // in the list since there is data in the stream.
  conn->streamManager->updatePeekableStreams(*stream);
  EXPECT_EQ(1, conn->streamManager->peekableStreams().count(streamId));
}

TEST_F(QuicTransportImplTest, UpdatePeekableListEmptyListTest) {
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);

  // Add some data to the stream.
  transport->addDataToStream(
      streamId,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  // Erase streamId from the list.
  conn->streamManager->peekableStreams().erase(streamId);
  EXPECT_EQ(0, conn->streamManager->peekableStreams().count(streamId));

  // After the call the streamId should be added to the list
  // because there is data in the stream and the streamId is
  // not in the list.
  conn->streamManager->updatePeekableStreams(*stream);
  EXPECT_EQ(1, conn->streamManager->peekableStreams().count(streamId));
}

TEST_F(QuicTransportImplTest, UpdatePeekableListWithStreamErrorTest) {
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  // Add some data to the stream.
  transport->addDataToStream(
      streamId,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  // streamId is in the list.
  EXPECT_EQ(1, conn->streamManager->peekableStreams().count(streamId));

  transport->addStreamReadError(streamId, LocalErrorCode::NO_ERROR);

  // peekableStreams is updated to allow stream with streamReadError.
  // So the streamId shall be in the list
  EXPECT_EQ(1, conn->streamManager->peekableStreams().count(streamId));
}

TEST_F(QuicTransportImplTest, SuccessfulPing) {
  auto conn = transport->transportConn;
  std::chrono::milliseconds interval(10);
  TestPingCallback pingCallback;
  transport->setPingCallback(&pingCallback);
  transport->invokeSendPing(interval);
  EXPECT_EQ(transport->isPingTimeoutScheduled(), true);
  EXPECT_EQ(conn->pendingEvents.cancelPingTimeout, false);
  conn->pendingEvents.cancelPingTimeout = true;
  transport->invokeHandlePingCallbacks();
  evb->loopOnce();
  EXPECT_EQ(transport->isPingTimeoutScheduled(), false);
  EXPECT_EQ(conn->pendingEvents.cancelPingTimeout, false);
}

TEST_F(QuicTransportImplTest, FailedPing) {
  auto conn = transport->transportConn;
  std::chrono::milliseconds interval(10);
  TestPingCallback pingCallback;
  transport->setPingCallback(&pingCallback);
  transport->invokeSendPing(interval);
  EXPECT_EQ(transport->isPingTimeoutScheduled(), true);
  EXPECT_EQ(conn->pendingEvents.cancelPingTimeout, false);
  conn->pendingEvents.cancelPingTimeout = true;
  transport->invokeCancelPingTimeout();
  transport->invokeHandlePingCallbacks();
  EXPECT_EQ(conn->pendingEvents.cancelPingTimeout, false);
}

TEST_F(QuicTransportImplTest, HandleKnobCallbacks) {
  auto conn = transport->transportConn;

  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::knobFrameEvents);

  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  transport->addObserver(obs1.get());
  transport->addObserver(obs2.get());
  transport->addObserver(obs3.get());

  // set test knob frame
  uint64_t knobSpace = 0xfaceb00c;
  uint64_t knobId = 42;
  folly::StringPiece data = "test knob data";
  Buf buf(folly::IOBuf::create(data.size()));
  memcpy(buf->writableData(), data.data(), data.size());
  buf->append(data.size());
  conn->pendingEvents.knobs.emplace_back(
      KnobFrame(knobSpace, knobId, std::move(buf)));

  EXPECT_CALL(connCallback, onKnobMock(knobSpace, knobId, _))
      .WillOnce(Invoke([](Unused, Unused, Unused) { /* do nothing */ }));
  EXPECT_CALL(*obs1, knobFrameReceived(transport.get(), _)).Times(0);
  EXPECT_CALL(*obs2, knobFrameReceived(transport.get(), _)).Times(1);
  EXPECT_CALL(*obs3, knobFrameReceived(transport.get(), _)).Times(1);
  transport->invokeHandleKnobCallbacks();
  evb->loopOnce();
  EXPECT_EQ(conn->pendingEvents.knobs.size(), 0);

  // detach the observer from the socket
  EXPECT_TRUE(transport->removeObserver(obs1.get()));
  EXPECT_TRUE(transport->removeObserver(obs2.get()));
  EXPECT_TRUE(transport->removeObserver(obs3.get()));
}

TEST_F(QuicTransportImplTest, StreamWriteCallbackUnregister) {
  auto stream = transport->createBidirectionalStream().value();
  // Unset before set
  EXPECT_FALSE(transport->unregisterStreamWriteCallback(stream));

  // Set
  auto wcb = std::make_unique<MockWriteCallback>();
  EXPECT_CALL(*wcb, onStreamWriteReady(stream, _)).Times(1);
  auto result = transport->notifyPendingWriteOnStream(stream, wcb.get());
  EXPECT_TRUE(result);
  evb->loopOnce();

  // Set then unset
  EXPECT_CALL(*wcb, onStreamWriteReady(stream, _)).Times(0);
  result = transport->notifyPendingWriteOnStream(stream, wcb.get());
  EXPECT_TRUE(result);
  EXPECT_TRUE(transport->unregisterStreamWriteCallback(stream));
  evb->loopOnce();

  // Set, close, unset
  result = transport->notifyPendingWriteOnStream(stream, wcb.get());
  EXPECT_TRUE(result);
  MockReadCallback rcb;
  transport->setReadCallback(stream, &rcb);
  // ReadCallback kills WriteCallback
  EXPECT_CALL(rcb, readError(stream, _))
      .WillOnce(Invoke([&](StreamId stream, auto) {
        EXPECT_TRUE(transport->unregisterStreamWriteCallback(stream));
        wcb.reset();
      }));
  transport->close(folly::none);
  evb->loopOnce();
}

TEST_F(QuicTransportImplTest, ObserverAttachRemove) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));
  EXPECT_CALL(*cb, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_F(QuicTransportImplTest, ObserverAttachRemoveMultiple) {
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb1, observerAttach(transport.get()));
  transport->addObserver(cb1.get());
  Mock::VerifyAndClearExpectations(cb1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb1.get()));

  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb2, observerAttach(transport.get()));
  transport->addObserver(cb2.get());
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_THAT(
      transport->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  EXPECT_CALL(*cb1, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb1.get()));
  Mock::VerifyAndClearExpectations(cb1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb2.get()));

  EXPECT_CALL(*cb2, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb2.get()));
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_F(QuicTransportImplTest, ObserverAttachRemoveMultipleReverse) {
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb1, observerAttach(transport.get()));
  transport->addObserver(cb1.get());
  Mock::VerifyAndClearExpectations(cb1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb1.get()));

  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb2, observerAttach(transport.get()));
  transport->addObserver(cb2.get());
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_THAT(
      transport->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  EXPECT_CALL(*cb2, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb2.get()));
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb1.get()));

  EXPECT_CALL(*cb1, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb1.get()));
  Mock::VerifyAndClearExpectations(cb1.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_F(QuicTransportImplTest, ObserverRemoveMissing) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_FALSE(transport->removeObserver(cb.get()));
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_F(QuicTransportImplTest, ObserverDestroyTransport) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));
  InSequence s;
  EXPECT_CALL(*cb, close(transport.get(), _));
  EXPECT_CALL(*cb, destroy(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_F(QuicTransportImplTest, ObserverCloseNoErrorThenDestroyTransport) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));

  const QuicError defaultError = QuicError(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *cb, close(transport.get(), folly::Optional<QuicError>(defaultError)));
  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(cb.get());
  InSequence s;
  EXPECT_CALL(*cb, destroy(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_F(QuicTransportImplTest, ObserverCloseWithErrorThenDestroyTransport) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));

  const auto testError = QuicError(
      QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
      std::string("testError"));
  EXPECT_CALL(
      *cb, close(transport.get(), folly::Optional<QuicError>(testError)));
  transport->close(testError);
  Mock::VerifyAndClearExpectations(cb.get());
  InSequence s;
  EXPECT_CALL(*cb, destroy(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_F(QuicTransportImplTest, ObserverDetachObserverImmediately) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));

  EXPECT_CALL(*cb, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_F(QuicTransportImplTest, ObserverDetachObserverAfterTransportClose) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));

  EXPECT_CALL(*cb, close(transport.get(), _));
  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(cb.get());

  EXPECT_CALL(*cb, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_F(
    QuicTransportImplTest,
    ObserverDetachObserverOnCloseDuringTransportDestroy) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));

  InSequence s;
  EXPECT_CALL(*cb, close(transport.get(), _))
      .WillOnce(Invoke([&cb](auto callbackTransport, auto /* errorOpt */) {
        EXPECT_TRUE(callbackTransport->removeObserver(cb.get()));
      }));
  EXPECT_CALL(*cb, observerDetach(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_F(QuicTransportImplTest, ObserverMultipleAttachRemove) {
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb1, observerAttach(transport.get()));
  transport->addObserver(cb1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb1.get()));

  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb2, observerAttach(transport.get()));
  transport->addObserver(cb2.get());
  EXPECT_THAT(
      transport->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  EXPECT_CALL(*cb2, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb2.get()));
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb1.get()));
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());

  EXPECT_CALL(*cb1, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb1.get()));
  EXPECT_THAT(transport->getObservers(), IsEmpty());
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());

  transport = nullptr;
}

TEST_F(QuicTransportImplTest, ObserverMultipleAttachDestroyTransport) {
  auto cb1 = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb1, observerAttach(transport.get()));
  transport->addObserver(cb1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb1.get()));

  auto cb2 = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb2, observerAttach(transport.get()));
  transport->addObserver(cb2.get());
  EXPECT_THAT(
      transport->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  InSequence s;
  EXPECT_CALL(*cb1, close(transport.get(), _));
  EXPECT_CALL(*cb2, close(transport.get(), _));
  EXPECT_CALL(*cb1, destroy(transport.get()));
  EXPECT_CALL(*cb2, destroy(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
}

TEST_F(QuicTransportImplTest, ObserverDetachAndAttachEvb) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::evbEvents);

  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  transport->addObserver(obs1.get());
  transport->addObserver(obs2.get());
  transport->addObserver(obs3.get());

  // check the current event base and create a new one
  EXPECT_EQ(evb.get(), transport->getEventBase());
  folly::EventBase evb2;

  // Detach the event base evb
  EXPECT_CALL(*obs1, evbDetach(transport.get(), evb.get())).Times(0);
  EXPECT_CALL(*obs2, evbDetach(transport.get(), evb.get())).Times(1);
  EXPECT_CALL(*obs3, evbDetach(transport.get(), evb.get())).Times(1);
  transport->detachEventBase();
  EXPECT_EQ(nullptr, transport->getEventBase());

  // Attach a new event base evb2
  EXPECT_CALL(*obs1, evbAttach(transport.get(), &evb2)).Times(0);
  EXPECT_CALL(*obs2, evbAttach(transport.get(), &evb2)).Times(1);
  EXPECT_CALL(*obs3, evbAttach(transport.get(), &evb2)).Times(1);
  transport->attachEventBase(&evb2);
  EXPECT_EQ(&evb2, transport->getEventBase());

  // Detach the event base evb2
  EXPECT_CALL(*obs1, evbDetach(transport.get(), &evb2)).Times(0);
  EXPECT_CALL(*obs2, evbDetach(transport.get(), &evb2)).Times(1);
  EXPECT_CALL(*obs3, evbDetach(transport.get(), &evb2)).Times(1);
  transport->detachEventBase();
  EXPECT_EQ(nullptr, transport->getEventBase());

  // Attach the original event base evb
  EXPECT_CALL(*obs1, evbAttach(transport.get(), evb.get())).Times(0);
  EXPECT_CALL(*obs2, evbAttach(transport.get(), evb.get())).Times(1);
  EXPECT_CALL(*obs3, evbAttach(transport.get(), evb.get())).Times(1);
  transport->attachEventBase(evb.get());
  EXPECT_EQ(evb.get(), transport->getEventBase());

  EXPECT_TRUE(transport->removeObserver(obs1.get()));
  EXPECT_TRUE(transport->removeObserver(obs2.get()));
  EXPECT_TRUE(transport->removeObserver(obs3.get()));
}

TEST_F(QuicTransportImplTest, GetConnectionStatsSmoke) {
  auto stats = transport->getConnectionsStats();
  EXPECT_EQ(stats.congestionController, CongestionControlType::Cubic);
  EXPECT_EQ(stats.clientConnectionId, "0a090807");
}

TEST_F(QuicTransportImplTest, DatagramCallbackDatagramAvailable) {
  NiceMock<MockDatagramCallback> datagramCb;
  transport->enableDatagram();
  transport->setDatagramCallback(&datagramCb);
  transport->addDatagram(folly::IOBuf::copyBuffer("datagram payload"));
  EXPECT_CALL(datagramCb, onDatagramsAvailable());
  transport->driveReadCallbacks();
}

TEST_F(QuicTransportImplTest, ZeroLengthDatagram) {
  NiceMock<MockDatagramCallback> datagramCb;
  transport->enableDatagram();
  transport->setDatagramCallback(&datagramCb);
  transport->addDatagram(folly::IOBuf::copyBuffer(""));
  EXPECT_CALL(datagramCb, onDatagramsAvailable());
  transport->driveReadCallbacks();
  auto datagrams = transport->readDatagramBufs();
  EXPECT_FALSE(datagrams.hasError());
  EXPECT_EQ(datagrams->size(), 1);
  EXPECT_TRUE(datagrams->front() != nullptr);
  EXPECT_EQ(datagrams->front()->computeChainDataLength(), 0);
}

TEST_F(QuicTransportImplTest, ZeroLengthDatagramBufs) {
  NiceMock<MockDatagramCallback> datagramCb;
  transport->enableDatagram();
  transport->setDatagramCallback(&datagramCb);
  auto recvTime = Clock::now() + 5000ns;
  transport->addDatagram(folly::IOBuf::copyBuffer(""), recvTime);
  EXPECT_CALL(datagramCb, onDatagramsAvailable());
  transport->driveReadCallbacks();
  auto datagrams = transport->readDatagrams();
  EXPECT_FALSE(datagrams.hasError());
  EXPECT_EQ(datagrams->size(), 1);
  EXPECT_TRUE(datagrams->front().bufQueue().front() != nullptr);
  EXPECT_EQ(datagrams->front().receiveTimePoint(), recvTime);
  EXPECT_EQ(datagrams->front().bufQueue().front()->computeChainDataLength(), 0);
}

TEST_F(QuicTransportImplTest, Cmsgs) {
  transport->setServerConnectionId();
  folly::SocketOptionMap cmsgs;
  cmsgs[{IPPROTO_IP, IP_TOS}] = 123;
  EXPECT_CALL(*socketPtr, setCmsgs(_)).Times(1);
  transport->setCmsgs(cmsgs);

  EXPECT_CALL(*socketPtr, appendCmsgs(_)).Times(1);
  transport->appendCmsgs(cmsgs);
}

TEST_F(QuicTransportImplTest, BackgroundModeChangeWithStreamChanges) {
  // Verify that background mode is correctly turned on and off
  // based upon stream creation, priority changes, stream removal.
  // For different steps try local (uni/bi)directional streams and remote
  // streams
  InSequence s;
  auto& conn = transport->getConnectionState();
  auto mockCongestionController =
      std::make_unique<NiceMock<MockCongestionController>>();
  auto rawCongestionController = mockCongestionController.get();
  conn.congestionController = std::move(mockCongestionController);
  auto& manager = *conn.streamManager;
  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(_))
      .Times(0); // Backgound params not set
  auto stream = manager.createNextUnidirectionalStream().value();
  manager.setStreamPriority(stream->id, 1, false);

  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(0.5))
      .Times(1); // On setting the background params
  transport->setBackgroundModeParameters(1, 0.5);

  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(0.5))
      .Times(1); // On removing a closed stream
  stream->sendState = StreamSendState::Closed;
  stream->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream->id);

  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(0.5))
      .Times(2); // On stream creation - create two streams - one bidirectional
  auto stream2Id = manager.createNextUnidirectionalStream().value()->id;
  auto stream3id = manager.createNextBidirectionalStream().value()->id;

  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(1.0))
      .Times(1); // On increasing the priority of one of the streams
  manager.setStreamPriority(stream3id, 0, false);

  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(1.0))
      .Times(1); // a new lower priority stream does not affect the utlization
                 // factor
  auto streamLower = manager.createNextBidirectionalStream().value();

  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(1.0))
      .Times(1); // On removing a closed stream
  streamLower->sendState = StreamSendState::Closed;
  streamLower->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(streamLower->id);

  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(0.5))
      .Times(1); // On removing a closed stream
  CHECK_NOTNULL(manager.getStream(stream3id))->sendState =
      StreamSendState::Closed;
  CHECK_NOTNULL(manager.getStream(stream3id))->recvState =
      StreamRecvState::Closed;
  manager.removeClosedStream(stream3id);

  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(0.5))
      .Times(1); // On stream creation - remote stream
  auto peerStreamId = 20;
  ASSERT_TRUE(isRemoteStream(conn.nodeType, peerStreamId));
  auto stream4 = manager.getStream(peerStreamId);

  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(1.0))
      .Times(1); // On clearing the background parameters
  transport->clearBackgroundModeParameters();

  EXPECT_CALL(*rawCongestionController, setBandwidthUtilizationFactor(_))
      .Times(0); // Background params not set
  stream4->sendState = StreamSendState::Closed;
  stream4->recvState = StreamRecvState::Closed;
  manager.removeClosedStream(stream4->id);
  CHECK_NOTNULL(manager.getStream(stream2Id))->sendState =
      StreamSendState::Closed;
  CHECK_NOTNULL(manager.getStream(stream2Id))->recvState =
      StreamRecvState::Closed;
  manager.removeClosedStream(stream2Id);
}

} // namespace test
} // namespace quic
