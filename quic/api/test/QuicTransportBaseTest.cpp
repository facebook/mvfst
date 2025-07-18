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
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/fizz/server/handshake/FizzServerQuicHandshakeContext.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/DatagramHandlers.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/stream/StreamSendHandlers.h>
#include <quic/state/test/MockQuicStats.h>
#include <quic/state/test/Mocks.h>

#include <quic/common/testutil/MockAsyncUDPSocket.h>
#include <memory>

using namespace testing;
using namespace folly;

namespace quic::test {

constexpr uint8_t kStreamIncrement = 0x04;

enum class TestFrameType : uint8_t {
  STREAM,
  CRYPTO,
  EXPIRED_DATA,
  REJECTED_DATA,
  MAX_STREAMS,
  DATAGRAM,
  STREAM_GROUP
};

// A made up encoding decoding of a stream.
BufPtr encodeStreamBuffer(
    StreamId id,
    StreamBuffer data,
    OptionalIntegral<StreamGroupId> groupId = std::nullopt) {
  auto buf = IOBuf::create(10);
  folly::io::Appender appender(buf.get(), 10);
  if (!groupId) {
    appender.writeBE(static_cast<uint8_t>(TestFrameType::STREAM));
  } else {
    appender.writeBE(static_cast<uint8_t>(TestFrameType::STREAM_GROUP));
  }
  appender.writeBE(id);
  if (groupId) {
    appender.writeBE(*groupId);
  }
  auto dataBuf = data.data.move();
  dataBuf->coalesce();
  appender.writeBE<uint32_t>(dataBuf->length());
  appender.push(dataBuf->coalesce());
  appender.writeBE<uint64_t>(data.offset);
  appender.writeBE<uint8_t>(data.eof);
  return buf;
}

BufPtr encodeCryptoBuffer(StreamBuffer data) {
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
BufPtr encodeMaxStreamsFrame(const MaxStreamsFrame& frame) {
  auto buf = IOBuf::create(25);
  folly::io::Appender appender(buf.get(), 25);
  appender.writeBE(static_cast<uint8_t>(TestFrameType::MAX_STREAMS));
  appender.writeBE<uint8_t>(frame.isForBidirectionalStream() ? 1 : 0);
  appender.writeBE<uint64_t>(frame.maxStreams);
  return buf;
}

// Build a datagram frame
BufPtr encodeDatagramFrame(BufQueue data) {
  auto buf = IOBuf::create(10);
  folly::io::Appender appender(buf.get(), 10);
  appender.writeBE(static_cast<uint8_t>(TestFrameType::DATAGRAM));
  auto dataBuf = data.move();
  dataBuf->coalesce();
  appender.writeBE<uint32_t>(dataBuf->length());
  appender.push(dataBuf->coalesce());
  return buf;
}

std::pair<BufPtr, uint32_t> decodeDatagramFrame(Cursor& cursor) {
  BufPtr outData;
  auto len = cursor.readBE<uint32_t>();
  cursor.clone(outData, len);
  return std::make_pair(std::move(outData), len);
}

std::pair<BufPtr, uint64_t> decodeDataBuffer(Cursor& cursor) {
  BufPtr outData;
  auto len = cursor.readBE<uint32_t>();
  cursor.clone(outData, len);
  uint64_t offset = cursor.readBE<uint64_t>();
  return std::make_pair(std::move(outData), offset);
}

std::pair<StreamId, StreamBuffer> decodeStreamBuffer(Cursor& cursor) {
  auto streamId = cursor.readBE<StreamId>();
  auto dataBuffer = decodeDataBuffer(cursor);
  bool eof = (bool)cursor.readBE<uint8_t>();
  return std::make_pair(
      streamId,
      StreamBuffer(std::move(dataBuffer.first), dataBuffer.second, eof));
}

struct StreamGroupIdBuf {
  StreamId id;
  StreamGroupId groupId;
  StreamBuffer buf;
};

StreamGroupIdBuf decodeStreamGroupBuffer(Cursor& cursor) {
  auto streamId = cursor.readBE<StreamId>();
  auto groupId = cursor.readBE<StreamGroupId>();
  auto dataBuffer = decodeDataBuffer(cursor);
  bool eof = (bool)cursor.readBE<uint8_t>();
  return StreamGroupIdBuf{
      streamId,
      groupId,
      StreamBuffer(std::move(dataBuffer.first), dataBuffer.second, eof)};
}

StreamBuffer decodeCryptoBuffer(Cursor& cursor) {
  auto dataBuffer = decodeDataBuffer(cursor);
  return StreamBuffer(std::move(dataBuffer.first), dataBuffer.second, false);
}

MaxStreamsFrame decodeMaxStreamsFrame(Cursor& cursor) {
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

class TestByteEventCallback : public ByteEventCallback {
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
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      ConnectionSetupCallback* connSetupCb,
      ConnectionCallback* connCb)
      : QuicTransportBaseLite(evb, std::move(socket)), QuicTransportBase(evb, nullptr /* Initialized through the QuicTransportBaseLite constructor */), observerContainer_(std::make_shared<SocketObserverContainer>(this)) {
    auto conn = std::make_unique<QuicServerConnectionState>(
        FizzServerQuicHandshakeContext::Builder().build());
    conn->clientConnectionId = ConnectionId::createAndMaybeCrash({10, 9, 8, 7});
    conn->version = QuicVersion::MVFST;
    conn->observerContainer = observerContainer_;
    transportConn = conn.get();
    conn_.reset(conn.release());
    aead = test::createNoOpAead();
    headerCipher = test::createNoOpHeaderCipher().value();
    connIdAlgo_ = std::make_unique<DefaultConnectionIdAlgo>();
    setConnectionSetupCallback(connSetupCb);
    setConnectionCallbackFromCtor(connCb);
  }

  ~TestQuicTransport() override {
    resetConnectionCallbacks();
    // we need to call close in the derived class.
    resetConnectionCallbacks();
    closeImpl(
        QuicError(
            QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
            std::string("shutdown")),
        false /* drainConnection */);
    // closeImpl may have been called earlier with drain = true, so force close.
    closeUdpSocket();
  }

  WriteResult writeBufMeta(
      StreamId /* id */,
      const BufferMeta& /* data */,
      bool /* eof */,
      ByteEventCallback* /* cb */) override {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  WriteResult setDSRPacketizationRequestSender(
      StreamId /* id */,
      std::unique_ptr<DSRPacketizationRequestSender> /* sender */) override {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  Optional<std::vector<TransportParameter>> getPeerTransportParams()
      const override {
    return std::nullopt;
  }

  std::chrono::milliseconds getLossTimeoutRemainingTime() {
    return lossTimeout_.getTimerCallbackTimeRemaining();
  }

  quic::Expected<void, QuicError> onReadData(
      const folly::SocketAddress&,
      ReceivedUdpPacket&& udpPacket) override {
    if (udpPacket.buf.empty()) {
      return {};
    }
    Cursor cursor(udpPacket.buf.front());
    while (!cursor.isAtEnd()) {
      // create server chosen connId with processId = 0 and workerId = 0
      ServerConnectionIdParams params(0, 0, 0);
      conn_->serverConnectionId = *connIdAlgo_->encodeConnectionId(params);
      auto type = static_cast<TestFrameType>(cursor.readBE<uint8_t>());
      if (type == TestFrameType::CRYPTO) {
        auto cryptoBuffer = decodeCryptoBuffer(cursor);
        auto cryptoResult = appendDataToReadBuffer(
            conn_->cryptoState->initialStream, std::move(cryptoBuffer));
        if (cryptoResult.hasError()) {
          return quic::make_unexpected(cryptoResult.error());
        }
      } else if (type == TestFrameType::MAX_STREAMS) {
        auto maxStreamsFrame = decodeMaxStreamsFrame(cursor);
        if (maxStreamsFrame.isForBidirectionalStream()) {
          auto bidirResult =
              conn_->streamManager->setMaxLocalBidirectionalStreams(
                  maxStreamsFrame.maxStreams);
          if (bidirResult.hasError()) {
            return quic::make_unexpected(bidirResult.error());
          }
        } else {
          auto unidirResult =
              conn_->streamManager->setMaxLocalUnidirectionalStreams(
                  maxStreamsFrame.maxStreams);
          if (unidirResult.hasError()) {
            return quic::make_unexpected(unidirResult.error());
          }
        }
      } else if (type == TestFrameType::DATAGRAM) {
        auto buffer = decodeDatagramFrame(cursor);
        auto frame = DatagramFrame(buffer.second, std::move(buffer.first));
        handleDatagram(*conn_, frame, udpPacket.timings.receiveTimePoint);
      } else if (type == TestFrameType::STREAM_GROUP) {
        auto res = decodeStreamGroupBuffer(cursor);
        auto streamResult =
            conn_->streamManager->getStream(res.id, res.groupId);
        if (streamResult.hasError()) {
          return quic::make_unexpected(streamResult.error());
        }
        QuicStreamState* stream = streamResult.value();
        if (!stream) {
          continue;
        }
        auto streamGroupResult =
            appendDataToReadBuffer(*stream, std::move(res.buf));
        if (streamGroupResult.hasError()) {
          return quic::make_unexpected(streamGroupResult.error());
        }
        conn_->streamManager->updateReadableStreams(*stream);
        conn_->streamManager->updatePeekableStreams(*stream);
      } else {
        auto buffer = decodeStreamBuffer(cursor);
        auto streamResult = conn_->streamManager->getStream(buffer.first);
        if (streamResult.hasError()) {
          return quic::make_unexpected(streamResult.error());
        }
        QuicStreamState* stream = streamResult.value();
        if (!stream) {
          continue;
        }
        auto result = appendDataToReadBuffer(*stream, std::move(buffer.second));
        if (result.hasError()) {
          return quic::make_unexpected(result.error());
        }
        conn_->streamManager->updateReadableStreams(*stream);
        conn_->streamManager->updatePeekableStreams(*stream);
      }
    }
    return {};
  }

  [[nodiscard]] quic::Expected<void, QuicError> writeData() override {
    auto result = writeQuicDataToSocket(
        *socket_,
        *conn_,
        conn_->serverConnectionId.value_or(ConnectionId::createZeroLength()),
        conn_->clientConnectionId.value_or(ConnectionId::createZeroLength()),
        *aead,
        *headerCipher,
        *conn_->version,
        conn_->transportSettings.writeConnectionDataPacketsLimit);
    if (result.hasError()) {
      return quic::make_unexpected(result.error());
    }
    return {};
  }

  // This is to expose the protected pacedWriteDataToSocket() function
  void pacedWriteDataToSocketThroughTransportBase() {
    pacedWriteDataToSocket();
  }

  bool hasWriteCipher() const {
    return conn_->oneRttWriteCipher != nullptr;
  }

  std::shared_ptr<QuicTransportBaseLite> sharedGuard() override {
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
    pingTimeout_.cancelTimerCallback();
  }

  void invokeHandlePingCallbacks() {
    handlePingCallbacks();
  }

  void invokeHandleKnobCallbacks() {
    handleKnobCallbacks();
  }

  bool isPingTimeoutScheduled() {
    return pingTimeout_.isTimerCallbackScheduled();
  }

  auto& writeLooper() {
    return writeLooper_;
  }

  auto& readLooper() {
    return readLooper_;
  }

  void unbindConnection() {}

  void onReadError(const folly::AsyncSocketException&) noexcept {}

  void addDataToStream(
      StreamId id,
      StreamBuffer data,
      OptionalIntegral<StreamGroupId> groupId = std::nullopt) {
    auto buf = encodeStreamBuffer(id, std::move(data), std::move(groupId));
    SocketAddress addr("127.0.0.1", 1000);
    onNetworkData(addr, NetworkData(std::move(buf), Clock::now(), 0));
  }

  void addCryptoData(StreamBuffer data) {
    auto buf = encodeCryptoBuffer(std::move(data));
    SocketAddress addr("127.0.0.1", 1000);
    onNetworkData(addr, NetworkData(std::move(buf), Clock::now(), 0));
  }

  void addMaxStreamsFrame(MaxStreamsFrame frame) {
    auto buf = encodeMaxStreamsFrame(frame);
    SocketAddress addr("127.0.0.1", 1000);
    onNetworkData(addr, NetworkData(std::move(buf), Clock::now(), 0));
  }

  void addStreamReadError(StreamId id, QuicErrorCode ex) {
    auto streamResult = conn_->streamManager->getStream(id);
    ASSERT_FALSE(streamResult.hasError());
    QuicStreamState* stream = streamResult.value();
    stream->streamReadError = ex;
    conn_->streamManager->updateReadableStreams(*stream);
    conn_->streamManager->updatePeekableStreams(*stream);
    // peekableStreams is updated to contain streams with streamReadError
    updatePeekLooper();
    updateReadLooper();
  }

  void addDatagram(BufPtr data, TimePoint recvTime = Clock::now()) {
    auto buf = encodeDatagramFrame(std::move(data));
    SocketAddress addr("127.0.0.1", 1000);
    onNetworkData(addr, NetworkData(std::move(buf), recvTime, 0));
  }

  void closeStream(StreamId id) {
    auto streamResult = conn_->streamManager->getStream(id);
    ASSERT_FALSE(streamResult.hasError());
    QuicStreamState* stream = streamResult.value();
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
    auto networkData = NetworkData(std::move(buf), Clock::now(), 0);
    onNetworkData(addr, std::move(networkData));
  }

  QuicStreamState* getStream(StreamId id) {
    return conn_->streamManager->getStream(id).value_or(nullptr);
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
    closeImpl(std::nullopt, false, false);
  }

  void invokeWriteSocketData() {
    CHECK(!writeSocketData().hasError());
  }

  [[nodiscard]] auto invokeWriteSocketDataReturn() {
    return writeSocketData();
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
    // Note: the RFC says to use 65535 to enable the datagram extension.
    // We are using +1 in tests to make sure that we avoid representing this
    // value with an uint16
    conn_->datagramState.maxReadFrameSize = 65536;
    conn_->datagramState.maxReadBufferSize = 10;
  }

  SocketObserverContainer* getSocketObserverContainer() const override {
    return observerContainer_.get();
  }

  Optional<std::vector<uint8_t>> getExportedKeyingMaterial(
      const std::string&,
      const Optional<ByteRange>&,
      uint16_t) const override {
    return std::nullopt;
  }

  void updateWriteLooper(bool thisIteration, bool /* runInline */ = false) {
    QuicTransportBase::updateWriteLooper(thisIteration);
  }

  void maybeStopWriteLooperAndArmSocketWritableEvent() {
    QuicTransportBase::maybeStopWriteLooperAndArmSocketWritableEvent();
  }

  void closeImpl(
      Optional<QuicError> error,
      bool drainConnection = true,
      bool sendCloseImmediately = true) {
    QuicTransportBase::closeImpl(
        std::move(error), drainConnection, sendCloseImmediately);
  }

  void onSocketWritable() noexcept override {
    QuicTransportBase::onSocketWritable();
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
    fEvb = std::make_unique<folly::EventBase>();
    qEvb = std::make_shared<FollyQuicEventBase>(fEvb.get());
    auto socket =
        std::make_unique<NiceMock<quic::test::MockAsyncUDPSocket>>(qEvb);
    ON_CALL(*socket, setAdditionalCmsgsFunc(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, close())
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, resumeWrite(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, bind(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, connect(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, setReuseAddr(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, setReusePort(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, setRecvTos(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, getRecvTos()).WillByDefault(Return(false));
    ON_CALL(*socket, getGSO()).WillByDefault(Return(0));
    ON_CALL(*socket, setCmsgs(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    ON_CALL(*socket, appendCmsgs(_))
        .WillByDefault(Return(quic::Expected<void, QuicError>{}));
    socketPtr = socket.get();
    transport = std::make_shared<TestQuicTransport>(
        qEvb, std::move(socket), &connSetupCallback, &connCallback);
    auto& conn = *transport->transportConn;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedInitialMaxStreamOffsetUni =
        kDefaultStreamFlowControlWindow;
    conn.flowControlState.peerAdvertisedMaxOffset =
        kDefaultConnectionFlowControlWindow;
    CHECK(
        !conn.streamManager
             ->setMaxLocalBidirectionalStreams(kDefaultMaxStreamsBidirectional)
             .hasError());
    CHECK(!conn.streamManager
               ->setMaxLocalUnidirectionalStreams(
                   kDefaultMaxStreamsUnidirectional)
               .hasError());
    maybeSetNotifyOnNewStreamsExplicitly();
  }

  virtual void maybeSetNotifyOnNewStreamsExplicitly() {}

  auto getTxMatcher(StreamId id, uint64_t offset) {
    return MockByteEventCallback::getTxMatcher(id, offset);
  }

  auto getAckMatcher(StreamId id, uint64_t offset) {
    return MockByteEventCallback::getAckMatcher(id, offset);
  }

 protected:
  std::unique_ptr<folly::EventBase> fEvb;
  std::shared_ptr<FollyQuicEventBase> qEvb;
  NiceMock<MockConnectionSetupCallback> connSetupCallback;
  NiceMock<MockConnectionCallback> connCallback;
  TestByteEventCallback byteEventCallback;
  std::shared_ptr<TestQuicTransport> transport;
  quic::test::MockAsyncUDPSocket* socketPtr;
};

class QuicTransportImplTestClose : public QuicTransportImplTest,
                                   public testing::WithParamInterface<bool> {};

INSTANTIATE_TEST_SUITE_P(
    QuicTransportImplTest,
    QuicTransportImplTestClose,
    Values(true, false));

struct DelayedStreamNotifsTestParam {
  bool notifyOnNewStreamsExplicitly;
};

class QuicTransportImplTestBase
    : public QuicTransportImplTest,
      public WithParamInterface<DelayedStreamNotifsTestParam> {
  void maybeSetNotifyOnNewStreamsExplicitly() override {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.notifyOnNewStreamsExplicitly =
        GetParam().notifyOnNewStreamsExplicitly;
    transport->setTransportSettings(transportSettings);
  }
};

INSTANTIATE_TEST_SUITE_P(
    QuicTransportImplTestBase,
    QuicTransportImplTestBase,
    ::testing::Values(
        DelayedStreamNotifsTestParam{false},
        DelayedStreamNotifsTestParam{true}));

TEST_P(QuicTransportImplTestBase, AckTimeoutExpiredWillResetTimeoutFlag) {
  transport->invokeAckTimeout();
  EXPECT_FALSE(transport->transportConn->pendingEvents.scheduleAckTimeout);
}

TEST_P(QuicTransportImplTestBase, IdleTimeoutExpiredDestroysTransport) {
  EXPECT_CALL(connSetupCallback, onConnectionSetupError(_))
      .WillOnce(Invoke([&](auto) { transport = nullptr; }));
  transport->invokeIdleTimeout();
}

TEST_P(QuicTransportImplTestBase, DelayConnCallback) {
  ASSERT_FALSE(transport->transportConn->streamManager
                   ->setMaxLocalBidirectionalStreams(0, /*force=*/true)
                   .hasError());
  transport->setConnectionCallback(nullptr);

  transport->addMaxStreamsFrame(
      MaxStreamsFrame(10, /*isBidirectionalIn=*/true));

  transport->setConnectionCallback(&connCallback);
  EXPECT_CALL(connCallback, onBidirectionalStreamsAvailable(_))
      .WillOnce(Invoke([](uint64_t numAvailableStreams) {
        EXPECT_EQ(numAvailableStreams, 10);
      }));
  transport->getEventBase()->loopOnce();
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, IdleTimeoutStreamMaessage) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  auto stream3 = transport->createUnidirectionalStream().value();
  transport->setControlStream(stream3);

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  ASSERT_TRUE(transport->setReadCallback(stream1, &readCb1).has_value());
  ASSERT_TRUE(transport->setReadCallback(stream2, &readCb2).has_value());

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

TEST_P(QuicTransportImplTestBase, StopSendingClosesIngress) {
  // update transport settings
  auto transportSettings = transport->getTransportSettings();
  transportSettings.dropIngressOnStopSending = true;
  transport->setTransportSettings(transportSettings);
  auto& streamManager = *transport->transportConn->streamManager;

  auto unknownErrorCode = GenericApplicationErrorCode::UNKNOWN;
  std::string ingressData = "some ingress stream data";
  auto ingressDataLen = ingressData.size();

  StreamId streamID;
  QuicStreamState* stream;

  // create bidirectional stream
  streamID = transport->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb1;
  ASSERT_TRUE(transport->setReadCallback(streamID, &readCb1).has_value());

  // add ingress & egress data to stream
  transport->addDataToStream(
      streamID, StreamBuffer(folly::IOBuf::copyBuffer(ingressData), 0));
  ASSERT_TRUE(transport
                  ->writeChain(
                      streamID,
                      folly::IOBuf::copyBuffer("some egress stream data"),
                      false)
                  .has_value());
  transport->driveReadCallbacks();
  stream = CHECK_NOTNULL(transport->getStream(streamID));

  // check stream has readable data and SM is open
  EXPECT_TRUE(stream->hasReadableData());
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);

  // send stop sending to peer – this and later invoking reset stream should not
  // invoke ReadCallback::readError()
  EXPECT_CALL(readCb1, readError(streamID, _)).Times(0);
  ASSERT_TRUE(
      transport->stopSending(streamID, GenericApplicationErrorCode::NO_ERROR)
          .has_value());

  // check that we've discarded any ingress data and ingress SM is closed
  EXPECT_FALSE(stream->hasReadableData());
  EXPECT_FALSE(streamManager.readableStreams().contains(streamID));
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Closed);

  // suppose we tx a rst stream (and rx its corresponding ack), expect
  // terminal state and queued in closed streams
  ASSERT_TRUE(
      transport->resetStream(streamID, GenericApplicationErrorCode::NO_ERROR)
          .has_value());
  ASSERT_FALSE(sendRstAckSMHandler(*stream, std::nullopt).hasError());
  EXPECT_TRUE(stream->inTerminalStates());
  EXPECT_TRUE(streamManager.closedStreams().contains(streamID));
  transport->driveReadCallbacks();

  // now if we rx a rst_stream we should deliver ReadCallback::readError()
  EXPECT_TRUE(streamManager.streamExists(streamID));
  EXPECT_CALL(readCb1, readError(streamID, QuicError(unknownErrorCode)))
      .Times(1);
  ASSERT_FALSE(
      receiveRstStreamSMHandler(
          *stream, RstStreamFrame(streamID, unknownErrorCode, ingressDataLen))
          .hasError());
  transport->readLooper()->runLoopCallback();

  // same test as above, but we tx a rst stream first followed by send stop
  // sending second to validate that .stopSending() queues stream to be closed
  NiceMock<MockReadCallback> readCb2;
  streamID = transport->createBidirectionalStream().value();
  ASSERT_FALSE(transport->setReadCallback(streamID, &readCb2).hasError());

  // add ingress & egress data to new stream
  transport->addDataToStream(
      streamID, StreamBuffer(folly::IOBuf::copyBuffer(ingressData), 0));
  ASSERT_FALSE(transport
                   ->writeChain(
                       streamID,
                       folly::IOBuf::copyBuffer("some egress stream data"),
                       false)
                   .hasError());
  transport->driveReadCallbacks();
  stream = CHECK_NOTNULL(transport->getStream(streamID));

  // check stream has readable data and SM is open
  EXPECT_TRUE(stream->hasReadableData());
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);

  // suppose we tx a rst stream (and rx its corresponding ack)
  ASSERT_FALSE(
      transport->resetStream(streamID, GenericApplicationErrorCode::NO_ERROR)
          .hasError());
  ASSERT_FALSE(sendRstAckSMHandler(*stream, std::nullopt).hasError());
  EXPECT_EQ(stream->sendState, StreamSendState::Closed);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);
  transport->driveReadCallbacks();

  // send stop sending to peer – does not deliver an error to the read callback
  // even tho the stream is in terminal state and queued for closing
  EXPECT_CALL(readCb2, readError(streamID, _)).Times(0);
  ASSERT_FALSE(
      transport->stopSending(streamID, GenericApplicationErrorCode::NO_ERROR)
          .hasError());

  // check that we've discarded any ingress data and ingress SM is closed,
  // expect terminal state and queued in closed streams
  EXPECT_FALSE(stream->hasReadableData());
  EXPECT_FALSE(streamManager.readableStreams().contains(streamID));
  EXPECT_TRUE(stream->inTerminalStates());
  EXPECT_TRUE(streamManager.closedStreams().contains(streamID));

  // we need to rx a rst stream before queue stream to be closed to allow
  // delivering callback to application
  EXPECT_CALL(readCb2, readError(streamID, QuicError(unknownErrorCode)))
      .Times(1);
  ASSERT_FALSE(
      receiveRstStreamSMHandler(
          *stream, RstStreamFrame(streamID, unknownErrorCode, ingressDataLen))
          .hasError());
  EXPECT_TRUE(stream->inTerminalStates());
  EXPECT_TRUE(streamManager.closedStreams().contains(streamID));
  transport->readLooper()->runLoopCallback();

  transport.reset();
}

TEST_P(QuicTransportImplTestBase, NoopStopSendingIngressClosed) {
  // create bidi stream
  auto streamID = transport->createBidirectionalStream().value();
  auto* stream = CHECK_NOTNULL(transport->getStream(streamID));

  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);

  // suppose we rx a reset from peer which closes our ingress SM
  ASSERT_FALSE(
      receiveRstStreamSMHandler(
          *stream,
          RstStreamFrame(stream->id, GenericApplicationErrorCode::NO_ERROR, 0))
          .hasError());
  EXPECT_EQ(stream->sendState, StreamSendState::Open);
  EXPECT_EQ(stream->recvState, StreamRecvState::Closed);

  // send stop sending to peer should no-op
  ASSERT_FALSE(
      transport->stopSending(streamID, GenericApplicationErrorCode::NO_ERROR)
          .hasError());
  EXPECT_EQ(transport->transportConn->pendingEvents.frames.size(), 0);

  // now test ingress uni-directional stream
  auto& streamManager = *transport->transportConn->streamManager;
  auto nextPeerUniStream =
      streamManager.nextAcceptablePeerUnidirectionalStreamId();
  EXPECT_TRUE(nextPeerUniStream.has_value());
  auto streamResult = streamManager.getStream(*nextPeerUniStream);
  ASSERT_FALSE(streamResult.hasError());
  stream = streamResult.value();
  EXPECT_EQ(stream->sendState, StreamSendState::Invalid);
  EXPECT_EQ(stream->recvState, StreamRecvState::Open);

  // suppose we rx a reset from peer which closes our ingress SM
  ASSERT_FALSE(
      receiveRstStreamSMHandler(
          *stream,
          RstStreamFrame(stream->id, GenericApplicationErrorCode::NO_ERROR, 0))
          .hasError());
  EXPECT_EQ(stream->sendState, StreamSendState::Invalid);
  EXPECT_EQ(stream->recvState, StreamRecvState::Closed);
  EXPECT_TRUE(stream->inTerminalStates());

  // send stop sending to peer should no-op
  ASSERT_FALSE(
      transport->stopSending(stream->id, GenericApplicationErrorCode::NO_ERROR)
          .hasError());
  EXPECT_EQ(transport->transportConn->pendingEvents.frames.size(), 0);

  transport.reset();
}

TEST_P(QuicTransportImplTestBase, WriteAckPacketUnsetsLooper) {
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
                  ->needsToSendAckImmediately);
  // Trigger the loop callback. This will trigger writes and we assume this will
  // write the acks since we have nothing else to write.
  transport->writeLooper()->runLoopCallback();
  EXPECT_FALSE(transport->transportConn->pendingEvents.scheduleAckTimeout);
  EXPECT_FALSE(transport->writeLooper()->isLoopCallbackScheduled());
}

TEST_P(QuicTransportImplTestBase, ReadCallbackDataAvailable) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  StreamId stream3 = 0x6;

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;
  NiceMock<MockReadCallback> readCb3;

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());
  ASSERT_FALSE(transport->setReadCallback(stream2, &readCb2).hasError());

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10));

  transport->addDataToStream(
      stream3, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  ASSERT_FALSE(transport->setReadCallback(stream3, &readCb3).hasError());

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
  ASSERT_FALSE(transport->setReadCallback(stream1, nullptr).hasError());
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReliableResetReadCallback) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb;

  ASSERT_FALSE(transport->setReadCallback(stream, &readCb).hasError());
  transport->addDataToStream(
      stream,
      StreamBuffer(
          folly::IOBuf::copyBuffer("this string has 29 characters"), 0));
  EXPECT_CALL(readCb, readAvailable(stream));
  transport->driveReadCallbacks();

  // Simulate receiving a reliable reset with a reliableSize of 29
  ASSERT_FALSE(
      receiveRstStreamSMHandler(
          *transport->getStream(stream),
          RstStreamFrame(stream, GenericApplicationErrorCode::UNKNOWN, 100, 29))
          .hasError());

  // The application hasn't yet read all of the reliable data, so we
  // shouldn't fire the readError callback yet.
  EXPECT_CALL(readCb, readAvailable(stream));
  transport->driveReadCallbacks();

  ASSERT_FALSE(transport->read(stream, 29).hasError());

  // The application has yet read all of the reliable data, so we should fire
  // the readError callback.
  EXPECT_CALL(
      readCb, readError(stream, IsError(GenericApplicationErrorCode::UNKNOWN)));
  transport->driveReadCallbacks();

  transport.reset();
}

TEST_P(
    QuicTransportImplTestBase,
    ReadCallbackDataAvailableWithUnidirPrioritized) {
  InSequence seq;

  auto transportSettings = transport->getTransportSettings();
  transportSettings.unidirectionalStreamsReadCallbacksFirst = true;
  transport->setTransportSettings(transportSettings);

  auto& streamManager = *transport->transportConn->streamManager;
  auto nextPeerUniStream =
      streamManager.nextAcceptablePeerUnidirectionalStreamId();
  EXPECT_TRUE(nextPeerUniStream.has_value());
  auto qpackStreamResult = streamManager.getStream(*nextPeerUniStream);
  ASSERT_FALSE(qpackStreamResult.hasError());
  StreamId qpackStream = qpackStreamResult.value()->id;

  auto requestStream = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> requestStreamCb;
  NiceMock<MockReadCallback> qpackStreamCb;

  ASSERT_FALSE(
      transport->setReadCallback(requestStream, &requestStreamCb).hasError());
  ASSERT_FALSE(
      transport->setReadCallback(qpackStream, &qpackStreamCb).hasError());

  transport->addDataToStream(
      qpackStream,
      StreamBuffer(
          folly::IOBuf::copyBuffer(
              "and i'm qpack data i will block you no tomorrow"),
          0));
  transport->addDataToStream(
      requestStream, StreamBuffer(folly::IOBuf::copyBuffer("i'm headers"), 0));

  bool qpackCbCalled = false;

  EXPECT_CALL(qpackStreamCb, readAvailable(qpackStream))
      .WillOnce(Invoke([&](StreamId) {
        EXPECT_FALSE(qpackCbCalled);
        qpackCbCalled = true;
      }));
  EXPECT_CALL(requestStreamCb, readAvailable(requestStream))
      .WillOnce(Invoke([&](StreamId) { EXPECT_TRUE(qpackCbCalled); }));
  transport->driveReadCallbacks();

  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadCallbackDataAvailableNoReap) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  StreamId stream3 = 0x6;

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;
  NiceMock<MockReadCallback> readCb3;

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());
  ASSERT_FALSE(transport->setReadCallback(stream2, &readCb2).hasError());

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10));

  transport->addDataToStream(
      stream3, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->driveReadCallbacks();

  ASSERT_FALSE(transport->setReadCallback(stream3, &readCb3).hasError());
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
  ASSERT_FALSE(transport->setReadCallback(stream1, nullptr).hasError());
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadCallbackDataAvailableOrdered) {
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

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());
  ASSERT_FALSE(transport->setReadCallback(stream2, &readCb2).hasError());

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10));

  transport->addDataToStream(
      stream3, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  ASSERT_FALSE(transport->setReadCallback(stream3, &readCb3).hasError());

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
  ASSERT_FALSE(transport->setReadCallback(stream1, nullptr).hasError());
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadCallbackChangeReadCallback) {
  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  EXPECT_TRUE(transport->setReadCallback(stream1, nullptr).hasError());

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->driveReadCallbacks();

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb2).hasError());
  EXPECT_CALL(readCb2, readAvailable(stream1));
  transport->driveReadCallbacks();

  auto& conn = transport->getConnectionState();
  EXPECT_EQ(conn.pendingEvents.frames.size(), 0);
  ASSERT_FALSE(transport->setReadCallback(stream1, nullptr).hasError());
  EXPECT_EQ(conn.pendingEvents.frames.size(), 1);
  EXPECT_CALL(readCb2, readAvailable(_)).Times(0);
  transport->driveReadCallbacks();

  EXPECT_TRUE(transport->setReadCallback(stream1, &readCb2).hasError());

  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadCallbackUnsetAll) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  // Set the read callbacks, and then add data to the stream, and see that the
  // callbacks are, in fact, called.

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());
  ASSERT_FALSE(transport->setReadCallback(stream2, &readCb2).hasError());

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

TEST_P(QuicTransportImplTestBase, ReadCallbackPauseResume) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());
  ASSERT_FALSE(transport->setReadCallback(stream2, &readCb2).hasError());

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

TEST_P(QuicTransportImplTestBase, ReadCallbackNoCallbackSet) {
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

TEST_P(QuicTransportImplTestBase, ReadCallbackInvalidStream) {
  NiceMock<MockReadCallback> readCb1;
  StreamId invalidStream = 10;
  EXPECT_TRUE(transport->setReadCallback(invalidStream, &readCb1).hasError());
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadData) {
  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());

  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->addDataToStream(stream1, StreamBuffer(readData->clone(), 0));
  transport->driveReadCallbacks();

  {
    auto readResult = transport->read(stream1, 10);
    ASSERT_TRUE(readResult.has_value());
    auto data = std::move(readResult).value();
    IOBufEqualTo eq;
    auto expected = readData->clone();
    expected->trimEnd(expected->length() - 10);
    EXPECT_TRUE(eq(*data.first, *expected));
  }

  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->driveReadCallbacks();
  {
    auto readResult = transport->read(stream1, 100);
    ASSERT_TRUE(readResult.has_value());
    auto data = std::move(readResult).value();
    IOBufEqualTo eq;
    auto expected = readData->clone();
    expected->trimStart(10);
    EXPECT_TRUE(eq(*data.first, *expected));
  }

  transport->driveReadCallbacks();
  transport.reset();
}

// TODO The finest copypasta around. We need a better story for parameterizing
// unidirectional vs. bidirectional.
TEST_P(QuicTransportImplTestBase, UnidirectionalReadData) {
  auto stream1 = 0x6;

  NiceMock<MockReadCallback> readCb1;
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  transport->addDataToStream(stream1, StreamBuffer(readData->clone(), 0));
  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());
  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->driveReadCallbacks();

  {
    auto readResult = transport->read(stream1, 10);
    ASSERT_TRUE(readResult.has_value());
    auto data = std::move(readResult).value();
    IOBufEqualTo eq;
    auto expected = readData->clone();
    expected->trimEnd(expected->length() - 10);
    EXPECT_TRUE(eq(*data.first, *expected));
  }

  EXPECT_CALL(readCb1, readAvailable(stream1));
  transport->driveReadCallbacks();
  {
    auto readResult2 = transport->read(stream1, 100);
    ASSERT_TRUE(readResult2.has_value());
    auto data = std::move(readResult2).value();
    IOBufEqualTo eq;
    auto expected = readData->clone();
    expected->trimStart(10);
    EXPECT_TRUE(eq(*data.first, *expected));
  }

  transport->driveReadCallbacks();
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadDataUnsetReadCallbackInCallback) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  NiceMock<MockReadCallback> readCb1;
  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());

  transport->addDataToStream(stream1, StreamBuffer(readData->clone(), 0, true));

  EXPECT_CALL(readCb1, readAvailable(stream1))
      .WillOnce(Invoke([&](StreamId id) {
        ASSERT_FALSE(transport->setReadCallback(id, nullptr).hasError());
      }));
  transport->driveReadCallbacks();
  transport->driveReadCallbacks();
  transport->getEventBase()->loop();
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadDataNoCallback) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  transport->addDataToStream(stream1, StreamBuffer(readData->clone(), 0, true));
  transport->driveReadCallbacks();
  {
    auto readResult = transport->read(stream1, 100);
    ASSERT_TRUE(readResult.has_value());
    auto data = std::move(readResult).value();
    IOBufEqualTo eq;
    EXPECT_TRUE(eq(*data.first, *readData));
    EXPECT_TRUE(data.second);
  }
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadCallbackForClientOutOfOrderStream) {
  auto const notifyOnNewStreamsExplicitly =
      transport->getTransportSettings().notifyOnNewStreamsExplicitly;

  InSequence dummy;
  StreamId clientOutOfOrderStream = 96;
  StreamId clientOutOfOrderStream2 = 76;

  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  NiceMock<MockReadCallback> streamRead;

  if (notifyOnNewStreamsExplicitly) {
    EXPECT_CALL(connCallback, onNewBidirectionalStream(clientOutOfOrderStream))
        .WillOnce(Invoke([&](StreamId id) {
          ASSERT_FALSE(transport->setReadCallback(id, &streamRead).hasError());
        }));
  } else {
    for (StreamId start = 0x00; start <= clientOutOfOrderStream;
         start += kStreamIncrement) {
      EXPECT_CALL(connCallback, onNewBidirectionalStream(start))
          .WillOnce(Invoke([&](StreamId id) {
            ASSERT_FALSE(
                transport->setReadCallback(id, &streamRead).hasError());
          }));
    }
  }

  EXPECT_CALL(streamRead, readAvailable(clientOutOfOrderStream))
      .WillOnce(Invoke([&](StreamId id) {
        auto readResult = transport->read(id, 100);
        ASSERT_TRUE(readResult.has_value());
        auto data = std::move(readResult).value();
        IOBufEqualTo eq;
        EXPECT_TRUE(eq(*data.first, *readData));
        EXPECT_TRUE(data.second);
      }));

  transport->addDataToStream(
      clientOutOfOrderStream, StreamBuffer(readData->clone(), 0, true));

  transport->driveReadCallbacks();

  if (notifyOnNewStreamsExplicitly) {
    EXPECT_CALL(connCallback, onNewBidirectionalStream(clientOutOfOrderStream2))
        .WillOnce(Invoke([&](StreamId id) {
          ASSERT_FALSE(transport->setReadCallback(id, &streamRead).hasError());
        }));
  }
  transport->addDataToStream(
      clientOutOfOrderStream2, StreamBuffer(readData->clone(), 0, true));

  EXPECT_CALL(streamRead, readAvailable(clientOutOfOrderStream2))
      .WillOnce(Invoke([&](StreamId id) {
        auto readResult = transport->read(id, 100);
        ASSERT_TRUE(readResult.has_value());
        auto data = std::move(readResult).value();
        IOBufEqualTo eq;
        EXPECT_TRUE(eq(*data.first, *readData));
        EXPECT_TRUE(data.second);
      }));
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadDataInvalidStream) {
  StreamId invalidStream = 10;
  auto readResult = transport->read(invalidStream, 100);
  EXPECT_FALSE(readResult.has_value());
  EXPECT_EQ(LocalErrorCode::STREAM_NOT_EXISTS, readResult.error());
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadError) {
  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());

  EXPECT_CALL(
      readCb1, readError(stream1, IsError(LocalErrorCode::STREAM_CLOSED)));
  transport->addStreamReadError(stream1, LocalErrorCode::STREAM_CLOSED);
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ReadCallbackDeleteTransport) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());
  ASSERT_FALSE(transport->setReadCallback(stream2, &readCb2).hasError());

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

TEST_P(QuicTransportImplTestBase, onNewBidirectionalStreamCallback) {
  auto const notifyOnNewStreamsExplicitly =
      transport->getTransportSettings().notifyOnNewStreamsExplicitly;

  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  StreamId stream2 = 0x00;
  EXPECT_CALL(connCallback, onNewBidirectionalStream(stream2));
  transport->addDataToStream(stream2, StreamBuffer(readData->clone(), 0, true));

  StreamId stream3 = 0x04;
  EXPECT_CALL(connCallback, onNewBidirectionalStream(stream3));
  transport->addDataToStream(stream3, StreamBuffer(readData->clone(), 0, true));

  StreamId uniStream3 = 0xa;
  if (!notifyOnNewStreamsExplicitly) {
    EXPECT_CALL(
        connCallback,
        onNewUnidirectionalStream(uniStream3 - 2 * kStreamIncrement));
    EXPECT_CALL(
        connCallback, onNewUnidirectionalStream(uniStream3 - kStreamIncrement));
  }
  EXPECT_CALL(connCallback, onNewUnidirectionalStream(uniStream3));
  transport->addDataToStream(
      uniStream3, StreamBuffer(readData->clone(), 0, true));
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, onNewStreamCallbackDoesNotRemove) {
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

TEST_P(QuicTransportImplTestBase, onNewBidirectionalStreamStreamOutOfOrder) {
  InSequence dummy;
  auto readData = folly::IOBuf::copyBuffer("actual stream data");
  StreamId biStream1 = 28;
  StreamId uniStream1 = 30;

  auto const notifyOnNewStreamsExplicitly =
      transport->getTransportSettings().notifyOnNewStreamsExplicitly;

  if (notifyOnNewStreamsExplicitly) {
    EXPECT_CALL(connCallback, onNewBidirectionalStream(biStream1));
    EXPECT_CALL(connCallback, onNewUnidirectionalStream(uniStream1));
  } else {
    for (StreamId id = 0x00; id <= biStream1; id += kStreamIncrement) {
      EXPECT_CALL(connCallback, onNewBidirectionalStream(id));
    }
    for (StreamId id = 0x02; id <= uniStream1; id += kStreamIncrement) {
      EXPECT_CALL(connCallback, onNewUnidirectionalStream(id));
    }
  }
  transport->addDataToStream(
      biStream1, StreamBuffer(readData->clone(), 0, true));
  transport->addDataToStream(
      uniStream1, StreamBuffer(readData->clone(), 0, true));

  StreamId biStream2 = 56;
  StreamId uniStream2 = 38;

  if (notifyOnNewStreamsExplicitly) {
    EXPECT_CALL(connCallback, onNewBidirectionalStream(biStream2));
    EXPECT_CALL(connCallback, onNewUnidirectionalStream(uniStream2));
  } else {
    for (StreamId id = biStream1 + kStreamIncrement; id <= biStream2;
         id += kStreamIncrement) {
      EXPECT_CALL(connCallback, onNewBidirectionalStream(id));
    }
    for (StreamId id = uniStream1 + kStreamIncrement; id <= uniStream2;
         id += kStreamIncrement) {
      EXPECT_CALL(connCallback, onNewUnidirectionalStream(id));
    }
  }

  transport->addDataToStream(
      biStream2, StreamBuffer(readData->clone(), 0, true));
  transport->addDataToStream(
      uniStream2, StreamBuffer(readData->clone(), 0, true));
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, onNewBidirectionalStreamSetReadCallback) {
  auto const notifyOnNewStreamsExplicitly =
      transport->getTransportSettings().notifyOnNewStreamsExplicitly;

  InSequence dummy;
  auto readData = folly::IOBuf::copyBuffer("actual stream data");
  transport->addCryptoData(StreamBuffer(readData->clone(), 0, true));

  NiceMock<MockReadCallback> stream2Read;
  StreamId stream2 = 0x00;
  EXPECT_CALL(connCallback, onNewBidirectionalStream(stream2))
      .WillOnce(Invoke([&](StreamId id) {
        ASSERT_FALSE(transport->setReadCallback(id, &stream2Read).hasError());
      }));
  transport->addDataToStream(stream2, StreamBuffer(readData->clone(), 0, true));

  StreamId stream3 = 0x10;
  NiceMock<MockReadCallback> streamRead;
  if (notifyOnNewStreamsExplicitly) {
    EXPECT_CALL(connCallback, onNewBidirectionalStream(stream3))
        .WillOnce(Invoke([&](StreamId id) {
          ASSERT_FALSE(transport->setReadCallback(id, &streamRead).hasError());
        }));
  } else {
    for (StreamId start = stream2 + kStreamIncrement; start <= stream3;
         start += kStreamIncrement) {
      EXPECT_CALL(connCallback, onNewBidirectionalStream(start))
          .WillOnce(Invoke([&](StreamId id) {
            ASSERT_FALSE(
                transport->setReadCallback(id, &streamRead).hasError());
          }));
    }
  }
  transport->addDataToStream(stream3, StreamBuffer(readData->clone(), 0, true));
  qEvb->loopOnce();
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, OnInvalidServerStream) {
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

TEST_P(QuicTransportImplTestBase, CreateStream) {
  auto streamId = transport->createBidirectionalStream().value();
  auto streamId2 = transport->createBidirectionalStream().value();
  auto streamId3 = transport->createBidirectionalStream().value();
  auto streamId4 = transport->createBidirectionalStream().value();

  EXPECT_EQ(streamId2, streamId + kStreamIncrement);
  EXPECT_EQ(streamId3, streamId2 + kStreamIncrement);
  EXPECT_EQ(streamId4, streamId3 + kStreamIncrement);
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, CreateUnidirectionalStream) {
  auto streamId = transport->createUnidirectionalStream().value();
  auto streamId2 = transport->createUnidirectionalStream().value();
  auto streamId3 = transport->createUnidirectionalStream().value();
  auto streamId4 = transport->createUnidirectionalStream().value();

  EXPECT_EQ(streamId2, streamId + kStreamIncrement);
  EXPECT_EQ(streamId3, streamId2 + kStreamIncrement);
  EXPECT_EQ(streamId4, streamId3 + kStreamIncrement);
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, CreateBothStream) {
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

TEST_P(QuicTransportImplTestBase, CreateStreamLimitsBidirectionalZero) {
  ASSERT_FALSE(transport->transportConn->streamManager
                   ->setMaxLocalBidirectionalStreams(0, true)
                   .hasError());
  EXPECT_EQ(transport->getNumOpenableBidirectionalStreams(), 0);
  auto result = transport->createBidirectionalStream();
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);
  result = transport->createUnidirectionalStream();
  EXPECT_TRUE(result);
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, CreateStreamLimitsUnidirectionalZero) {
  ASSERT_FALSE(transport->transportConn->streamManager
                   ->setMaxLocalUnidirectionalStreams(0, true)
                   .hasError());
  EXPECT_EQ(transport->getNumOpenableUnidirectionalStreams(), 0);
  auto result = transport->createUnidirectionalStream();
  ASSERT_FALSE(result);
  EXPECT_EQ(result.error(), LocalErrorCode::STREAM_LIMIT_EXCEEDED);
  result = transport->createBidirectionalStream();
  EXPECT_TRUE(result);
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, CreateStreamLimitsBidirectionalFew) {
  ASSERT_FALSE(transport->transportConn->streamManager
                   ->setMaxLocalBidirectionalStreams(10, true)
                   .hasError());
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

TEST_P(QuicTransportImplTestBase, CreateStreamLimitsUnidirectionalFew) {
  ASSERT_FALSE(transport->transportConn->streamManager
                   ->setMaxLocalUnidirectionalStreams(10, true)
                   .hasError());
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

TEST_P(QuicTransportImplTestBase, onBidiStreamsAvailableCallback) {
  ASSERT_FALSE(transport->transportConn->streamManager
                   ->setMaxLocalBidirectionalStreams(0, /*force=*/true)
                   .hasError());

  EXPECT_CALL(connCallback, onBidirectionalStreamsAvailable(_))
      .WillOnce(Invoke([](uint64_t numAvailableStreams) {
        EXPECT_EQ(numAvailableStreams, 10);
      }));
  transport->addMaxStreamsFrame(
      MaxStreamsFrame(10, /*isBidirectionalIn=*/true));
  EXPECT_EQ(transport->getNumOpenableBidirectionalStreams(), 10);

  // same value max streams frame doesn't trigger callback
  transport->addMaxStreamsFrame(
      MaxStreamsFrame(10, /*isBidirectionalIn=*/true));
}

TEST_P(QuicTransportImplTestBase, onBidiStreamsAvailableCallbackAfterExausted) {
  ASSERT_FALSE(transport->transportConn->streamManager
                   ->setMaxLocalBidirectionalStreams(0, /*force=*/true)
                   .hasError());

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

TEST_P(QuicTransportImplTestBase, oneUniStreamsAvailableCallback) {
  ASSERT_FALSE(transport->transportConn->streamManager
                   ->setMaxLocalUnidirectionalStreams(0, /*force=*/true)
                   .hasError());

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

TEST_P(QuicTransportImplTestBase, onUniStreamsAvailableCallbackAfterExausted) {
  ASSERT_FALSE(transport->transportConn->streamManager
                   ->setMaxLocalUnidirectionalStreams(0, /*force=*/true)
                   .hasError());

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

TEST_P(QuicTransportImplTestBase, ReadDataAlsoChecksLossAlarm) {
  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();
  auto stream = transport->createBidirectionalStream().value();
  ASSERT_FALSE(
      transport->writeChain(stream, folly::IOBuf::copyBuffer("Hey"), true)
          .hasError());
  // Artificially stop the write looper so that the read can trigger it.
  transport->writeLooper()->stop();
  transport->addDataToStream(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("Data"), 0));
  EXPECT_TRUE(transport->writeLooper()->isRunning());
  // Drive the event loop once to allow for the write looper to continue.
  qEvb->loopOnce();
  EXPECT_TRUE(transport->isLossTimeoutScheduled());
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, ConnectionErrorOnWrite) {
  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();
  auto stream = transport->createBidirectionalStream().value();
  EXPECT_CALL(*socketPtr, write(_, _, _))
      .WillOnce(SetErrnoAndReturn(ENETUNREACH, -1));
  ASSERT_FALSE(
      transport
          ->writeChain(stream, folly::IOBuf::copyBuffer("Hey"), true, nullptr)
          .hasError());
  transport->addDataToStream(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("Data"), 0));
  qEvb->loopOnce();

  EXPECT_TRUE(transport->isClosed());
  EXPECT_EQ(
      transport->getConnectionError(),
      QuicErrorCode(LocalErrorCode::CONNECTION_ABANDONED));
}

TEST_P(QuicTransportImplTestBase, ReadErrorUnsanitizedErrorMsg) {
  transport->setServerConnectionId();
  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();
  auto stream = transport->createBidirectionalStream().value();
  MockReadCallback rcb;
  ASSERT_FALSE(transport->setReadCallback(stream, &rcb).hasError());
  EXPECT_CALL(rcb, readError(stream, _))
      .Times(1)
      .WillOnce(Invoke([](StreamId, QuicError error) {
        EXPECT_EQ("You need to calm down.", error.message);
      }));

  EXPECT_CALL(*socketPtr, write(_, _, _))
      .WillOnce(
          Invoke([](const folly::SocketAddress&, const struct iovec*, size_t) {
            throw std::runtime_error("You need to calm down.");
            return 0;
          }));
  auto writeChain_tmp = transport->writeChain(
      stream,
      folly::IOBuf::copyBuffer("You are being too loud."),
      true,
      nullptr);
  qEvb->loopOnce();

  EXPECT_TRUE(transport->isClosed());
}

TEST_P(QuicTransportImplTestBase, ConnectionErrorUnhandledException) {
  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();
  auto stream = transport->createBidirectionalStream().value();
  EXPECT_CALL(
      connSetupCallback,
      onConnectionSetupError(QuicError(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::string("Well there's your problem"))));
  EXPECT_CALL(*socketPtr, write(_, _, _))
      .WillOnce(
          Invoke([](const folly::SocketAddress&, const struct iovec*, size_t) {
            throw std::runtime_error("Well there's your problem");
            return 0;
          }));
  ASSERT_FALSE(
      transport
          ->writeChain(stream, folly::IOBuf::copyBuffer("Hey"), true, nullptr)
          .hasError());
  transport->addDataToStream(
      stream, StreamBuffer(folly::IOBuf::copyBuffer("Data"), 0));
  qEvb->loopOnce();

  EXPECT_TRUE(transport->isClosed());
  EXPECT_EQ(
      transport->getConnectionError(),
      QuicErrorCode(TransportErrorCode::INTERNAL_ERROR));
}

TEST_P(QuicTransportImplTestBase, LossTimeoutNoLessThanTickInterval) {
  auto tickInterval = qEvb->getTimerTickInterval();
  transport->scheduleLossTimeout(tickInterval - 1ms);
  EXPECT_NEAR(
      tickInterval.count(),
      transport->getLossTimeoutRemainingTime().count(),
      2);
}

TEST_P(QuicTransportImplTestBase, CloseStreamAfterReadError) {
  auto qLogger = std::make_shared<FileQLogger>(VantagePoint::Client);
  transport->transportConn->qLogger = qLogger;
  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockReadCallback> readCb1;
  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());

  transport->addStreamReadError(stream1, LocalErrorCode::NO_ERROR);
  transport->closeStream(stream1);

  EXPECT_CALL(readCb1, readError(stream1, IsError(LocalErrorCode::NO_ERROR)));
  EXPECT_CALL(connCallback, onStreamPreReaped(stream1));
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

TEST_P(QuicTransportImplTestBase, CloseStreamAfterReadFin) {
  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockReadCallback> readCb2;
  ASSERT_FALSE(transport->setReadCallback(stream2, &readCb2).hasError());

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

TEST_P(QuicTransportImplTestBase, CloseTransportCleansupOutstandingCounters) {
  transport->transportConn->outstandings
      .packetCount[PacketNumberSpace::Handshake] = 200;
  transport->closeNow(std::nullopt);
  EXPECT_EQ(
      0,
      transport->transportConn->outstandings
          .packetCount[PacketNumberSpace::Handshake]);
}

TEST_P(QuicTransportImplTestBase, DeliveryCallbackUnsetAll) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;

  auto registerDelivery1 =
      transport->registerDeliveryCallback(stream1, 10, &dcb1);
  auto registerDelivery2 =
      transport->registerDeliveryCallback(stream2, 20, &dcb2);

  EXPECT_CALL(dcb1, onCanceled(_, _));
  EXPECT_CALL(dcb2, onCanceled(_, _));

  transport->unsetAllDeliveryCallbacks();

  EXPECT_CALL(dcb1, onCanceled(_, _)).Times(0);
  EXPECT_CALL(dcb2, onCanceled(_, _)).Times(0);

  transport->close(std::nullopt);
}

TEST_P(QuicTransportImplTestBase, DeliveryCallbackUnsetOne) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;

  auto registerDelivery3 =
      transport->registerDeliveryCallback(stream1, 10, &dcb1);
  auto registerDelivery4 =
      transport->registerDeliveryCallback(stream2, 20, &dcb2);

  EXPECT_CALL(dcb1, onCanceled(_, _));
  EXPECT_CALL(dcb2, onCanceled(_, _)).Times(0);

  transport->cancelDeliveryCallbacksForStream(stream1);

  EXPECT_CALL(dcb1, onCanceled(_, _)).Times(0);
  EXPECT_CALL(dcb2, onCanceled(_, _));

  transport->close(std::nullopt);
}

TEST_P(QuicTransportImplTestBase, ByteEventCallbacksManagementSingleStream) {
  auto stream = transport->createBidirectionalStream().value();
  uint64_t offset1 = 10, offset2 = 20;

  ByteEvent txEvent1 = ByteEvent{stream, offset1, ByteEvent::Type::TX};
  ByteEvent txEvent2 = ByteEvent{stream, offset2, ByteEvent::Type::TX};
  ByteEvent ackEvent1 = ByteEvent{stream, offset1, ByteEvent::Type::ACK};
  ByteEvent ackEvent2 = ByteEvent{stream, offset2, ByteEvent::Type::ACK};

  // Register 2 TX and 2 ACK events for the same stream at 2 different offsets
  ASSERT_FALSE(
      transport
          ->registerTxCallback(txEvent1.id, txEvent1.offset, &byteEventCallback)
          .hasError());
  ASSERT_FALSE(
      transport
          ->registerTxCallback(txEvent2.id, txEvent2.offset, &byteEventCallback)
          .hasError());
  auto registerByteEvent1 = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, ackEvent1.id, ackEvent1.offset, &byteEventCallback);
  auto registerByteEvent2 = transport->registerByteEventCallback(
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
  quic::Expected<void, LocalErrorCode> ret;
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

TEST_P(
    QuicTransportImplTestBase,
    ByteEventCallbacksManagementDifferentStreams) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  ByteEvent txEvent1 = ByteEvent{stream1, 10, ByteEvent::Type::TX};
  ByteEvent txEvent2 = ByteEvent{stream2, 20, ByteEvent::Type::TX};
  ByteEvent ackEvent1 = ByteEvent{stream1, 10, ByteEvent::Type::ACK};
  ByteEvent ackEvent2 = ByteEvent{stream2, 20, ByteEvent::Type::ACK};

  EXPECT_THAT(byteEventCallback.getByteEventTracker(), IsEmpty());
  // Register 2 TX and 2 ACK events for 2 separate streams.
  auto registerTx1 = transport->registerTxCallback(
      txEvent1.id, txEvent1.offset, &byteEventCallback);
  auto registerTx2 = transport->registerTxCallback(
      txEvent2.id, txEvent2.offset, &byteEventCallback);
  auto registerByteEvent3 = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, ackEvent1.id, ackEvent1.offset, &byteEventCallback);
  auto registerByteEvent4 = transport->registerByteEventCallback(
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

TEST_P(QuicTransportImplTestBase, RegisterTxDeliveryCallbackLowerThanExpected) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;
  StrictMock<MockByteEventCallback> txcb3;
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;
  NiceMock<MockDeliveryCallback> dcb3;

  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream, 10)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream, 20)));
  auto registerTx3 = transport->registerTxCallback(stream, 10, &txcb1);
  auto registerTx4 = transport->registerTxCallback(stream, 20, &txcb2);
  auto registerDelivery5 =
      transport->registerDeliveryCallback(stream, 10, &dcb1);
  auto registerDelivery6 =
      transport->registerDeliveryCallback(stream, 20, &dcb2);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  auto streamStateResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamStateResult.hasError());
  auto streamState = streamStateResult.value();
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  EXPECT_CALL(txcb3, onByteEventRegistered(getTxMatcher(stream, 2)));
  EXPECT_CALL(txcb3, onByteEvent(getTxMatcher(stream, 2)));
  EXPECT_CALL(dcb3, onDeliveryAck(stream, 2, _));
  auto registerTx5 = transport->registerTxCallback(stream, 2, &txcb3);
  auto registerDelivery7 =
      transport->registerDeliveryCallback(stream, 2, &dcb3);
  qEvb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb3);
  Mock::VerifyAndClearExpectations(&dcb3);

  EXPECT_CALL(txcb1, onByteEventCanceled(getTxMatcher(stream, 10)));
  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream, 20)));
  EXPECT_CALL(dcb1, onCanceled(_, _));
  EXPECT_CALL(dcb2, onCanceled(_, _));
  transport->close(std::nullopt);
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
  auto streamStateResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamStateResult.hasError());
  auto streamState = streamStateResult.value();
  streamState->currentWriteOffset = 7;

  EXPECT_CALL(txcb, onByteEventRegistered(getTxMatcher(stream, 2)));
  EXPECT_CALL(txcb, onByteEventCanceled(getTxMatcher(stream, 2)));
  EXPECT_CALL(dcb, onCanceled(_, _));
  auto registerTx6 = transport->registerTxCallback(stream, 2, &txcb);
  auto registerDelivery8 = transport->registerDeliveryCallback(stream, 2, &dcb);
  transport->close(std::nullopt);
  qEvb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb);
  Mock::VerifyAndClearExpectations(&dcb);
}

TEST_P(
    QuicTransportImplTestBase,
    RegisterDeliveryCallbackMultipleRegistrationsTx) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamStateResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamStateResult.hasError());
  auto streamState = streamStateResult.value();
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Have 2 different recipients register for a callback on the same stream ID
  // and offset that is before the current write offset, they will both be
  // scheduled for immediate delivery.
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream, 3)));
  auto registerTx7 = transport->registerTxCallback(stream, 3, &txcb1);
  auto registerTx8 = transport->registerTxCallback(stream, 3, &txcb2);
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
  qEvb->loopOnce();
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
  auto streamStateResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamStateResult.hasError());
  auto streamState = streamStateResult.value();
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Have 2 different recipients register for a callback on the same stream ID
  // and offset that is before the current write offset, they will both be
  // scheduled for immediate delivery.
  EXPECT_CALL(txcb1, onByteEventRegistered(getAckMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getAckMatcher(stream, 3)));
  auto registerByteEvent5 = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, stream, 3, &txcb1);
  auto registerByteEvent6 = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, stream, 3, &txcb2);
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
  qEvb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_P(
    QuicTransportImplTestBase,
    RegisterDeliveryCallbackMultipleRecipientsTx) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamStateResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamStateResult.hasError());
  auto streamState = streamStateResult.value();
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Have 2 different recipients register for a callback on the same stream ID
  // and offset.
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream, 3)));
  auto registerTx9 = transport->registerTxCallback(stream, 3, &txcb1);
  auto registerTx10 = transport->registerTxCallback(stream, 3, &txcb2);
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
  qEvb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_P(
    QuicTransportImplTestBase,
    RegisterDeliveryCallbackMultipleRecipientsAck) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamStateResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamStateResult.hasError());
  auto streamState = streamStateResult.value();
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Have 2 different recipients register for a callback on the same stream ID
  // and offset.
  EXPECT_CALL(txcb1, onByteEventRegistered(getAckMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getAckMatcher(stream, 3)));
  auto registerByteEvent7 = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, stream, 3, &txcb1);
  auto registerByteEvent8 = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, stream, 3, &txcb2);
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
  qEvb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_P(QuicTransportImplTestBase, RegisterDeliveryCallbackAsyncDeliveryTx) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamStateResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamStateResult.hasError());
  auto streamState = streamStateResult.value();
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Register tx callbacks for the same stream at offsets 3 (before current
  // write offset) and 10 (after current write offset).
  // txcb1 (offset = 3) will be scheduled in the lambda (runOnEvbAsync)
  // for immediate delivery. txcb2 (offset = 10) will be queued for delivery
  // when the actual TX for this offset occurs in the future.
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream, 10)));
  auto registerTx11 = transport->registerTxCallback(stream, 3, &txcb1);
  auto registerTx12 = transport->registerTxCallback(stream, 10, &txcb2);
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
  qEvb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  EXPECT_CALL(txcb2, onByteEventCanceled(getTxMatcher(stream, 10)));
  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_P(QuicTransportImplTestBase, RegisterDeliveryCallbackAsyncDeliveryAck) {
  auto stream = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;

  // Set the current write offset to 7.
  auto streamStateResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamStateResult.hasError());
  auto streamState = streamStateResult.value();
  streamState->currentWriteOffset = 7;
  streamState->ackedIntervals.insert(0, 6);

  // Register tx callbacks for the same stream at offsets 3 (before current
  // write offset) and 10 (after current write offset).
  // txcb1 (offset = 3) will be scheduled in the lambda (runOnEvbAsync)
  // for immediate delivery. txcb2 (offset = 10) will be queued for delivery
  // when the actual TX for this offset occurs in the future.
  EXPECT_CALL(txcb1, onByteEventRegistered(getAckMatcher(stream, 3)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getAckMatcher(stream, 10)));
  auto registerByteEvent9 = transport->registerByteEventCallback(
      ByteEvent::Type::ACK, stream, 3, &txcb1);
  auto registerByteEvent10 = transport->registerByteEventCallback(
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
  qEvb->loopOnce();
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);

  EXPECT_CALL(txcb2, onByteEventCanceled(getAckMatcher(stream, 10)));
  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&txcb2);
}

TEST_P(QuicTransportImplTestBase, CancelAllByteEventCallbacks) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  NiceMock<MockByteEventCallback> txcb1;
  NiceMock<MockByteEventCallback> txcb2;
  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 20)));
  auto registerTx13 = transport->registerTxCallback(stream1, 10, &txcb1);
  auto registerTx14 = transport->registerTxCallback(stream2, 20, &txcb2);

  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;
  auto registerDelivery9 =
      transport->registerDeliveryCallback(stream1, 10, &dcb1);
  auto registerDelivery10 =
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

  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);
}

TEST_P(QuicTransportImplTestBase, CancelByteEventCallbacksForStream) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  StrictMock<MockByteEventCallback> txcb1;
  StrictMock<MockByteEventCallback> txcb2;
  NiceMock<MockDeliveryCallback> dcb1;
  NiceMock<MockDeliveryCallback> dcb2;

  EXPECT_CALL(txcb1, onByteEventRegistered(getTxMatcher(stream1, 10)));
  EXPECT_CALL(txcb2, onByteEventRegistered(getTxMatcher(stream2, 20)));
  auto registerTx15 = transport->registerTxCallback(stream1, 10, &txcb1);
  auto registerTx16 = transport->registerTxCallback(stream2, 20, &txcb2);
  auto registerDelivery11 =
      transport->registerDeliveryCallback(stream1, 10, &dcb1);
  auto registerDelivery12 =
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

  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);
}

TEST_P(QuicTransportImplTestBase, CancelByteEventCallbacksForStreamWithOffset) {
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
  auto registerTx17 = transport->registerTxCallback(stream1, 10, &txcb1);
  auto registerTx18 = transport->registerTxCallback(stream1, 15, &txcb1);
  auto registerTx19 = transport->registerTxCallback(stream1, 20, &txcb1);
  auto registerTx20 = transport->registerTxCallback(stream2, 10, &txcb2);
  auto registerTx21 = transport->registerTxCallback(stream2, 15, &txcb2);
  auto registerTx22 = transport->registerTxCallback(stream2, 20, &txcb2);

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

  auto registerDelivery13 =
      transport->registerDeliveryCallback(stream1, 10, &dcb1);
  auto registerDelivery14 =
      transport->registerDeliveryCallback(stream1, 15, &dcb1);
  auto registerDelivery15 =
      transport->registerDeliveryCallback(stream1, 20, &dcb1);
  auto registerDelivery16 =
      transport->registerDeliveryCallback(stream2, 10, &dcb2);
  auto registerDelivery17 =
      transport->registerDeliveryCallback(stream2, 15, &dcb2);
  auto registerDelivery18 =
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

  transport->close(std::nullopt);
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

TEST_P(QuicTransportImplTestBase, CancelByteEventCallbacksTx) {
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
  auto registerTx23 = transport->registerTxCallback(stream1, 10, &txcb1);
  auto registerTx24 = transport->registerTxCallback(stream1, 15, &txcb1);
  auto registerTx25 = transport->registerTxCallback(stream2, 10, &txcb2);
  auto registerTx26 = transport->registerTxCallback(stream2, 15, &txcb2);
  auto registerDelivery19 =
      transport->registerDeliveryCallback(stream1, 10, &dcb1);
  auto registerDelivery20 =
      transport->registerDeliveryCallback(stream1, 15, &dcb1);
  auto registerDelivery21 =
      transport->registerDeliveryCallback(stream2, 10, &dcb2);
  auto registerDelivery22 =
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

  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);
}

TEST_P(QuicTransportImplTestBase, CancelByteEventCallbacksDelivery) {
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
  auto registerTx27 = transport->registerTxCallback(stream1, 10, &txcb1);
  auto registerTx28 = transport->registerTxCallback(stream1, 15, &txcb1);
  auto registerTx29 = transport->registerTxCallback(stream2, 10, &txcb2);
  auto registerTx30 = transport->registerTxCallback(stream2, 15, &txcb2);
  auto registerDelivery23 =
      transport->registerDeliveryCallback(stream1, 10, &dcb1);
  auto registerDelivery24 =
      transport->registerDeliveryCallback(stream1, 15, &dcb1);
  auto registerDelivery25 =
      transport->registerDeliveryCallback(stream2, 10, &dcb2);
  auto registerDelivery26 =
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

  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(&txcb1);
  Mock::VerifyAndClearExpectations(&txcb2);
  Mock::VerifyAndClearExpectations(&dcb1);
  Mock::VerifyAndClearExpectations(&dcb2);
}

TEST_P(
    QuicTransportImplTestBase,
    TestNotifyPendingConnWriteOnCloseWithoutError) {
  NiceMock<MockWriteCallback> wcb;
  EXPECT_CALL(
      wcb,
      onConnectionWriteError(IsError(GenericApplicationErrorCode::NO_ERROR)));
  auto notifyWrite1 = transport->notifyPendingWriteOnConnection(&wcb);
  transport->close(std::nullopt);
  qEvb->loopOnce();
}

TEST_P(QuicTransportImplTestClose, TestNotifyPendingConnWriteOnCloseWithError) {
  NiceMock<MockWriteCallback> wcb;
  auto notifyWrite2 = transport->notifyPendingWriteOnConnection(&wcb);
  if (GetParam()) {
    EXPECT_CALL(
        wcb,
        onConnectionWriteError(
            IsAppError(GenericApplicationErrorCode::UNKNOWN)));
    transport->close(QuicError(
        QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
        std::string("Bye")));
  } else {
    transport->close(std::nullopt);
  }
  qEvb->loopOnce();
}

TEST_P(QuicTransportImplTestBase, TestNotifyPendingWriteWithActiveCallback) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  EXPECT_CALL(wcb, onStreamWriteReady(stream, _));
  auto ok1 = transport->notifyPendingWriteOnStream(stream, &wcb);
  EXPECT_TRUE(ok1.has_value());
  auto ok2 = transport->notifyPendingWriteOnStream(stream, &wcb);
  EXPECT_EQ(ok2.error(), quic::LocalErrorCode::CALLBACK_ALREADY_INSTALLED);
  qEvb->loopOnce();
}

TEST_P(QuicTransportImplTestBase, TestNotifyPendingWriteOnCloseWithoutError) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  EXPECT_CALL(
      wcb,
      onStreamWriteError(
          stream, IsError(GenericApplicationErrorCode::NO_ERROR)));
  auto notifyWrite3 = transport->notifyPendingWriteOnStream(stream, &wcb);
  transport->close(std::nullopt);
  qEvb->loopOnce();
}

TEST_P(QuicTransportImplTestClose, TestNotifyPendingWriteOnCloseWithError) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  auto notifyWrite4 = transport->notifyPendingWriteOnStream(stream, &wcb);
  if (GetParam()) {
    EXPECT_CALL(
        wcb,
        onStreamWriteError(
            stream, IsAppError(GenericApplicationErrorCode::UNKNOWN)));
    transport->close(QuicError(
        QuicErrorCode(GenericApplicationErrorCode::UNKNOWN),
        std::string("Bye")));
  } else {
    transport->close(std::nullopt);
  }
  qEvb->loopOnce();
}

TEST_P(QuicTransportImplTestBase, TestTransportCloseWithMaxPacketNumber) {
  transport->setServerConnectionId();
  transport->transportConn->pendingEvents.closeTransport = false;
  ASSERT_FALSE(transport->invokeWriteSocketDataReturn().hasError());

  transport->transportConn->pendingEvents.closeTransport = true;
  auto result = transport->invokeWriteSocketDataReturn();
  ASSERT_TRUE(result.hasError());
  ASSERT_NE(result.error().code.asTransportErrorCode(), nullptr);
  EXPECT_EQ(
      *result.error().code.asTransportErrorCode(),
      TransportErrorCode::PROTOCOL_VIOLATION);
}

TEST_P(QuicTransportImplTestBase, TestGracefulCloseWithActiveStream) {
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

  auto notifyWrite5 = transport->notifyPendingWriteOnConnection(&wcbConn);
  auto notifyWrite6 = transport->notifyPendingWriteOnStream(stream, &wcb);
  ASSERT_FALSE(transport->setReadCallback(stream, &rcb).hasError());
  EXPECT_CALL(*socketPtr, write(_, _, _))
      .WillRepeatedly(SetErrnoAndReturn(EAGAIN, -1));
  ASSERT_FALSE(
      transport
          ->writeChain(stream, IOBuf::copyBuffer("hello"), true, &deliveryCb)
          .hasError());
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
  auto streamResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_FALSE(streamResult.value()->readBuffer.empty());

  // Close the last stream.
  // TODO: replace this when we call conn callbacks.
  // EXPECT_CALL(connCallback, onConnectionEnd());
  transport->closeStream(stream);
  ASSERT_TRUE(transport->transportClosed);

  qEvb->loopOnce();
}

TEST_P(QuicTransportImplTestBase, TestGracefulCloseWithNoActiveStream) {
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

  ASSERT_FALSE(transport->setReadCallback(stream, &rcb).hasError());
  EXPECT_CALL(*socketPtr, write(_, _, _))
      .WillRepeatedly(SetErrnoAndReturn(EAGAIN, -1));
  ASSERT_FALSE(
      transport
          ->writeChain(stream, IOBuf::copyBuffer("hello"), true, &deliveryCb)
          .hasError());
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 0)));
  EXPECT_CALL(txCb, onByteEventRegistered(getTxMatcher(stream, 4)));
  EXPECT_FALSE(transport->registerTxCallback(stream, 0, &txCb).hasError());
  EXPECT_FALSE(transport->registerTxCallback(stream, 4, &txCb).hasError());

  // Close the last stream.
  auto streamStateResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamStateResult.hasError());
  auto streamState = streamStateResult.value();
  // Fake that the data was TXed and delivered to keep all the state
  // consistent.
  streamState->currentWriteOffset = 7;
  transport->transportConn->streamManager->addTx(stream);
  transport->transportConn->streamManager->addDeliverable(stream);
  transport->closeStream(stream);
  transport->close(std::nullopt);

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

TEST_P(QuicTransportImplTestBase, TestResetRemovesDeliveryCb) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockDeliveryCallback> deliveryCb1;
  NiceMock<MockDeliveryCallback> deliveryCb2;
  EXPECT_CALL(*socketPtr, write(_, _, _))
      .WillRepeatedly(SetErrnoAndReturn(EAGAIN, -1));
  ASSERT_FALSE(
      transport->writeChain(stream1, IOBuf::copyBuffer("hello"), true, nullptr)
          .hasError());
  ASSERT_FALSE(
      transport->writeChain(stream2, IOBuf::copyBuffer("hello"), true, nullptr)
          .hasError());
  EXPECT_FALSE(
      transport->registerDeliveryCallback(stream1, 2, &deliveryCb1).hasError());
  EXPECT_FALSE(
      transport->registerDeliveryCallback(stream2, 2, &deliveryCb2).hasError());
  EXPECT_EQ(transport->getNumByteEventCallbacksForStream(stream1), 1);
  EXPECT_EQ(transport->getNumByteEventCallbacksForStream(stream2), 1);
  EXPECT_FALSE(
      transport->resetStream(stream1, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
  EXPECT_EQ(transport->getNumByteEventCallbacksForStream(stream1), 0);
  EXPECT_EQ(transport->getNumByteEventCallbacksForStream(stream2), 1);
  transport->close(std::nullopt);
}

TEST_P(QuicTransportImplTestBase, TestImmediateClose) {
  auto stream = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  NiceMock<MockWriteCallback> wcbConn;
  NiceMock<MockReadCallback> rcb;
  NiceMock<MockReadCallback> rcb2;
  NiceMock<MockPeekCallback> pcb;
  NiceMock<MockDeliveryCallback> deliveryCb;
  NiceMock<MockByteEventCallback> txCb;
  uint8_t resetCount = 0;
  EXPECT_CALL(
      wcb,
      onStreamWriteError(
          stream, IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  EXPECT_CALL(
      wcbConn,
      onConnectionWriteError(IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  // The first stream to get a reset will clear the other read callback, so only
  // one will receive a reset.
  ON_CALL(
      rcb, readError(stream, IsAppError(GenericApplicationErrorCode::UNKNOWN)))
      .WillByDefault(InvokeWithoutArgs([this, stream2, &resetCount] {
        (void)transport->setReadCallback(stream2, nullptr);
        resetCount++;
      }));
  ON_CALL(
      rcb2,
      readError(stream2, IsAppError(GenericApplicationErrorCode::UNKNOWN)))
      .WillByDefault(InvokeWithoutArgs([this, stream, &resetCount] {
        (void)transport->setReadCallback(stream, nullptr);
        resetCount++;
      }));
  EXPECT_CALL(
      pcb, peekError(stream, IsAppError(GenericApplicationErrorCode::UNKNOWN)));
  EXPECT_CALL(deliveryCb, onCanceled(stream, _));
  EXPECT_CALL(txCb, onByteEventCanceled(getTxMatcher(stream, 0)));
  EXPECT_CALL(txCb, onByteEventCanceled(getTxMatcher(stream, 4)));

  EXPECT_CALL(connCallback, onConnectionError(_)).Times(0);

  auto notifyWrite7 = transport->notifyPendingWriteOnConnection(&wcbConn);
  auto notifyWrite8 = transport->notifyPendingWriteOnStream(stream, &wcb);
  ASSERT_FALSE(transport->setReadCallback(stream, &rcb).hasError());
  ASSERT_FALSE(transport->setReadCallback(stream2, &rcb2).hasError());
  auto setPeek1 = transport->setPeekCallback(stream, &pcb);
  EXPECT_CALL(*socketPtr, write(_, _, _))
      .WillRepeatedly(SetErrnoAndReturn(EAGAIN, -1));
  ASSERT_FALSE(
      transport
          ->writeChain(stream, IOBuf::copyBuffer("hello"), true, &deliveryCb)
          .hasError());
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
  auto streamResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamResult.hasError());
  EXPECT_EQ(streamResult.value(), nullptr);
  qEvb->loopOnce();
  EXPECT_EQ(resetCount, 1);
}

TEST_P(QuicTransportImplTestBase, ResetStreamUnsetWriteCallback) {
  auto stream = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb;
  EXPECT_CALL(wcb, onStreamWriteError(stream, _)).Times(0);
  auto notifyWrite9 = transport->notifyPendingWriteOnStream(stream, &wcb);
  EXPECT_FALSE(
      transport->resetStream(stream, GenericApplicationErrorCode::UNKNOWN)
          .hasError());
  qEvb->loopOnce();
}

TEST_P(QuicTransportImplTestBase, ResetAllNonControlStreams) {
  auto stream1 = transport->createBidirectionalStream().value();
  ASSERT_FALSE(transport->setControlStream(stream1));
  NiceMock<MockWriteCallback> wcb1;
  NiceMock<MockReadCallback> rcb1;
  EXPECT_CALL(wcb1, onStreamWriteError(stream1, _)).Times(0);
  EXPECT_CALL(rcb1, readError(stream1, _)).Times(0);
  auto notifyWrite10 = transport->notifyPendingWriteOnStream(stream1, &wcb1);
  ASSERT_FALSE(transport->setReadCallback(stream1, &rcb1).hasError());

  auto stream2 = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb2;
  NiceMock<MockReadCallback> rcb2;
  EXPECT_CALL(wcb2, onStreamWriteError(stream2, _)).Times(1);
  EXPECT_CALL(rcb2, readError(stream2, _)).Times(1);
  auto notifyWrite11 = transport->notifyPendingWriteOnStream(stream2, &wcb2);
  ASSERT_FALSE(transport->setReadCallback(stream2, &rcb2).hasError());

  auto stream3 = transport->createUnidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb3;
  auto notifyWrite12 = transport->notifyPendingWriteOnStream(stream3, &wcb3);
  EXPECT_CALL(wcb3, onStreamWriteError(stream3, _)).Times(1);

  auto stream4 = transport->createBidirectionalStream().value();
  NiceMock<MockWriteCallback> wcb4;
  NiceMock<MockReadCallback> rcb4;
  EXPECT_CALL(wcb4, onStreamWriteError(stream4, _))
      .WillOnce(Invoke([&](auto, auto) {
        ASSERT_FALSE(transport->setReadCallback(stream4, nullptr).hasError());
      }));
  EXPECT_CALL(rcb4, readError(_, _)).Times(0);
  auto notifyWrite13 = transport->notifyPendingWriteOnStream(stream4, &wcb4);
  ASSERT_FALSE(transport->setReadCallback(stream4, &rcb4).hasError());

  transport->resetNonControlStreams(
      GenericApplicationErrorCode::UNKNOWN, "bye bye");
  qEvb->loopOnce();

  // Have to manually unset the read callbacks so they aren't use-after-freed.
  transport->unsetAllReadCallbacks();
}

TEST_P(QuicTransportImplTestBase, DestroyWithoutClosing) {
  EXPECT_CALL(connCallback, onConnectionError(_)).Times(0);
  EXPECT_CALL(connCallback, onConnectionEnd()).Times(0);
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, UncleanShutdownEventBase) {
  // if abruptly shutting down the eventbase we should avoid scheduling
  // any new timer.
  transport->setIdleTimeout();
  qEvb.reset();
}

TEST_P(QuicTransportImplTestBase, GetLocalAddressBoundSocket) {
  SocketAddress addr("127.0.0.1", 443);
  EXPECT_CALL(*socketPtr, isBound()).WillOnce(Return(true));
  EXPECT_CALL(*socketPtr, addressRef()).WillRepeatedly(ReturnRef(addr));
  SocketAddress localAddr = transport->getLocalAddress();
  EXPECT_TRUE(localAddr == addr);
}

TEST_P(QuicTransportImplTestBase, GetLocalAddressUnboundSocket) {
  EXPECT_CALL(*socketPtr, isBound()).WillOnce(Return(false));
  SocketAddress localAddr = transport->getLocalAddress();
  EXPECT_FALSE(localAddr.isInitialized());
}

TEST_P(QuicTransportImplTestBase, GetLocalAddressBadSocket) {
  auto badTransport = std::make_shared<TestQuicTransport>(
      qEvb, nullptr, &connSetupCallback, &connCallback);
  badTransport->closeWithoutWrite();
  SocketAddress localAddr = badTransport->getLocalAddress();
  EXPECT_FALSE(localAddr.isInitialized());
}

TEST_P(QuicTransportImplTestBase, AsyncStreamFlowControlWrite) {
  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();
  auto stream = transport->createBidirectionalStream().value();
  auto streamStateResult =
      transport->transportConn->streamManager->getStream(stream);
  ASSERT_FALSE(streamStateResult.hasError());
  auto streamState = streamStateResult.value();
  transport->setServerConnectionId();
  transport->writeLooper()->stop();
  streamState->flowControlState.advertisedMaxOffset = 0; // Easier to calculate
  auto setFlow1 = transport->setStreamFlowControlWindow(stream, 4000);
  EXPECT_EQ(0, streamState->flowControlState.advertisedMaxOffset);
  // Loop it:
  EXPECT_TRUE(transport->writeLooper()->isRunning());
  transport->writeLooper()->runLoopCallback();
  EXPECT_EQ(4000, streamState->flowControlState.advertisedMaxOffset);
}

TEST_P(QuicTransportImplTestBase, ExceptionInWriteLooperDoesNotCrash) {
  auto stream = transport->createBidirectionalStream().value();
  (void)transport->setReadCallback(stream, nullptr);
  ASSERT_FALSE(
      transport->writeChain(stream, IOBuf::copyBuffer("hello"), true, nullptr)
          .hasError());
  transport->addDataToStream(
      stream, StreamBuffer(IOBuf::copyBuffer("hello"), 0, false));
  EXPECT_CALL(*socketPtr, write(_, _, _))
      .WillOnce(SetErrnoAndReturn(EBADF, -1));
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

TEST_P(QuicTransportImplTestBase, UnidirectionalInvalidReadFuncs) {
  auto stream = transport->createUnidirectionalStream().value();
  EXPECT_FALSE(transport->read(stream, 100).has_value());
  EXPECT_FALSE(transport->setReadCallback(stream, nullptr).has_value());
  EXPECT_FALSE(transport->pauseRead(stream).has_value());
  EXPECT_FALSE(transport->resumeRead(stream).has_value());
  EXPECT_FALSE(
      transport->stopSending(stream, GenericApplicationErrorCode::UNKNOWN)
          .has_value());
}

TEST_P(QuicTransportImplTestBase, UnidirectionalInvalidWriteFuncs) {
  auto readData = folly::IOBuf::copyBuffer("actual stream data");
  StreamId stream = 0x6;
  transport->addDataToStream(stream, StreamBuffer(readData->clone(), 0, true));
  EXPECT_FALSE(transport->getStreamWriteOffset(stream).has_value());
  EXPECT_FALSE(transport->getStreamWriteBufferedBytes(stream).has_value());
  EXPECT_FALSE(
      transport->notifyPendingWriteOnStream(stream, nullptr).has_value());
  EXPECT_FALSE(
      transport->writeChain(stream, folly::IOBuf::copyBuffer("Hey"), false)
          .has_value());
  EXPECT_FALSE(
      transport->registerDeliveryCallback(stream, 0, nullptr).has_value());
  EXPECT_FALSE(transport->registerTxCallback(stream, 0, nullptr).has_value());
  EXPECT_FALSE(
      transport
          ->registerByteEventCallback(ByteEvent::Type::ACK, stream, 0, nullptr)
          .has_value());
  EXPECT_FALSE(
      transport
          ->registerByteEventCallback(ByteEvent::Type::TX, stream, 0, nullptr)
          .has_value());
  EXPECT_FALSE(
      transport->resetStream(stream, GenericApplicationErrorCode::UNKNOWN)
          .has_value());
}

TEST_P(QuicTransportImplTestUniBidi, IsServerStream) {
  auto stream = createStream(transport, GetParam());
  EXPECT_TRUE(transport->isServerStream(stream));
}

TEST_P(QuicTransportImplTestUniBidi, IsClientStream) {
  auto stream = createStream(transport, GetParam());
  EXPECT_FALSE(transport->isClientStream(stream));
}

TEST_P(QuicTransportImplTestBase, IsUnidirectionalStream) {
  auto stream = transport->createUnidirectionalStream().value();
  EXPECT_TRUE(transport->isUnidirectionalStream(stream));
}

TEST_P(QuicTransportImplTestBase, IsBidirectionalStream) {
  auto stream = transport->createBidirectionalStream().value();
  EXPECT_TRUE(transport->isBidirectionalStream(stream));
}

TEST_P(QuicTransportImplTestBase, GetStreamDirectionalityUnidirectional) {
  auto stream = transport->createUnidirectionalStream().value();
  EXPECT_EQ(
      StreamDirectionality::Unidirectional,
      transport->getStreamDirectionality(stream));
}

TEST_P(QuicTransportImplTestBase, GetStreamDirectionalityBidirectional) {
  auto stream = transport->createBidirectionalStream().value();
  EXPECT_EQ(
      StreamDirectionality::Bidirectional,
      transport->getStreamDirectionality(stream));
}

TEST_P(QuicTransportImplTestBase, PeekCallbackDataAvailable) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  NiceMock<MockPeekCallback> peekCb1;
  NiceMock<MockPeekCallback> peekCb2;

  auto setPeek2 = transport->setPeekCallback(stream1, &peekCb1);
  auto setPeek3 = transport->setPeekCallback(stream2, &peekCb2);

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

  auto setPeek4 = transport->setPeekCallback(stream1, nullptr);
  auto setPeek5 = transport->setPeekCallback(stream2, nullptr);
  transport->driveReadCallbacks();

  transport.reset();
}

TEST_P(QuicTransportImplTestBase, PeekError) {
  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockPeekCallback> peekCb1;
  auto setPeek6 = transport->setPeekCallback(stream1, &peekCb1);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));
  transport->addStreamReadError(stream1, LocalErrorCode::STREAM_CLOSED);

  EXPECT_CALL(
      peekCb1, peekError(stream1, IsError(LocalErrorCode::STREAM_CLOSED)));

  transport->driveReadCallbacks();

  EXPECT_CALL(peekCb1, peekError(stream1, _));

  transport.reset();
}

TEST_P(QuicTransportImplTestBase, PeekCallbackUnsetAll) {
  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  NiceMock<MockPeekCallback> peekCb1;
  NiceMock<MockPeekCallback> peekCb2;

  // Set the peek callbacks and add data to the streams, and see that the
  // callbacks do indeed fire

  auto setPeek7 = transport->setPeekCallback(stream1, &peekCb1);
  auto setPeek8 = transport->setPeekCallback(stream2, &peekCb2);

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

TEST_P(QuicTransportImplTestBase, PeekCallbackChangePeekCallback) {
  InSequence enforceOrder;

  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockPeekCallback> peekCb1;
  NiceMock<MockPeekCallback> peekCb2;

  auto setPeek9 = transport->setPeekCallback(stream1, &peekCb1);

  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(peekCb1, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  auto setPeek10 = transport->setPeekCallback(stream1, &peekCb2);
  transport->addDataToStream(
      stream1, StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  EXPECT_CALL(peekCb2, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, PeekCallbackPauseResume) {
  InSequence enforceOrder;

  auto stream1 = transport->createBidirectionalStream().value();
  NiceMock<MockPeekCallback> peekCb1;

  auto setPeek11 = transport->setPeekCallback(stream1, &peekCb1);

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

TEST_P(QuicTransportImplTestBase, PeekCallbackNoCallbackSet) {
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

TEST_P(QuicTransportImplTestBase, PeekCallbackInvalidStream) {
  NiceMock<MockPeekCallback> peekCb1;
  StreamId invalidStream = 10;
  EXPECT_TRUE(transport->setPeekCallback(invalidStream, &peekCb1).hasError());
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, PeekData) {
  InSequence enforceOrder;

  auto stream1 = transport->createBidirectionalStream().value();

  NiceMock<MockPeekCallback> peekCb1;
  auto peekData = folly::IOBuf::copyBuffer("actual stream data");

  auto setPeek12 = transport->setPeekCallback(stream1, &peekCb1);

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
    EXPECT_EQ("actual stream data", bufClone->to<std::string>());
  };

  auto peekResult = transport->peek(stream1, peekCallback);
  EXPECT_TRUE(cbCalled);
  transport.reset();
}

TEST_P(QuicTransportImplTestBase, PeekDataWithError) {
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

TEST_P(QuicTransportImplTestBase, ConsumeDataWithError) {
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

TEST_P(QuicTransportImplTestBase, PeekConsumeReadTest) {
  InSequence enforceOrder;

  auto stream1 = transport->createBidirectionalStream().value();
  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  NiceMock<MockPeekCallback> peekCb;
  NiceMock<MockReadCallback> readCb;

  auto setPeek13 = transport->setPeekCallback(stream1, &peekCb);
  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb).hasError());

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
  auto transportConsumeResult1 = transport->consume(stream1, 5);

  // Both peek and read should be called.
  // Read - because it is called every time
  // Peek - because the peekable range has changed
  EXPECT_CALL(readCb, readAvailable(stream1));
  EXPECT_CALL(peekCb, onDataAvailable(stream1, _));
  transport->driveReadCallbacks();

  // Read 10 bytes.
  {
    auto readResult = transport->read(stream1, 10);
    ASSERT_TRUE(readResult.has_value());
    auto data = std::move(readResult).value();
    EXPECT_EQ("l stream d", data.first->to<std::string>());
  }

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
  auto transportConsumeResult2 = transport->consume(stream1, 42);

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
  auto transportConsumeResult3 =
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
  {
    auto readResult = transport->read(stream1, 0);
    ASSERT_TRUE(readResult.has_value());
    auto data = std::move(readResult).value();
    EXPECT_EQ(
        " Here is my number, so call me maybe.", data.first->to<std::string>());
  }

  // Neither read nor peek should be called.
  EXPECT_CALL(readCb, readAvailable(stream1)).Times(0);
  EXPECT_CALL(peekCb, onDataAvailable(stream1, _)).Times(0);
  transport->driveReadCallbacks();

  transport.reset();
}

TEST_P(QuicTransportImplTestBase, UpdatePeekableListNoDataTest) {
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);

  // Insert streamId into the list.
  conn->streamManager->peekableStreams().insert(streamId);
  // After the call the streamId should be removed
  // from the list since there is no peekable data in the stream.
  conn->streamManager->updatePeekableStreams(*stream);
  EXPECT_FALSE(conn->streamManager->peekableStreams().contains(streamId));
}

TEST_P(QuicTransportImplTestBase, UpdatePeekableListWithDataTest) {
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);

  // Add some data to the stream.
  transport->addDataToStream(
      streamId,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  // streamId is in the list after the above call.
  EXPECT_TRUE(conn->streamManager->peekableStreams().contains(streamId));

  // After the call the streamId shall remain
  // in the list since there is data in the stream.
  conn->streamManager->updatePeekableStreams(*stream);
  EXPECT_TRUE(conn->streamManager->peekableStreams().contains(streamId));
}

TEST_P(QuicTransportImplTestBase, UpdatePeekableListEmptyListTest) {
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);

  // Add some data to the stream.
  transport->addDataToStream(
      streamId,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  // Erase streamId from the list.
  conn->streamManager->peekableStreams().erase(streamId);
  EXPECT_FALSE(conn->streamManager->peekableStreams().contains(streamId));

  // After the call the streamId should be added to the list
  // because there is data in the stream and the streamId is
  // not in the list.
  conn->streamManager->updatePeekableStreams(*stream);
  EXPECT_TRUE(conn->streamManager->peekableStreams().contains(streamId));
}

TEST_P(QuicTransportImplTestBase, UpdatePeekableListWithStreamErrorTest) {
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  // Add some data to the stream.
  transport->addDataToStream(
      streamId,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0));

  // streamId is in the list.
  EXPECT_TRUE(conn->streamManager->peekableStreams().contains(streamId));

  transport->addStreamReadError(streamId, LocalErrorCode::NO_ERROR);

  // peekableStreams is updated to allow stream with streamReadError.
  // So the streamId shall be in the list
  EXPECT_TRUE(conn->streamManager->peekableStreams().contains(streamId));
}

TEST_P(QuicTransportImplTestBase, SuccessfulPing) {
  auto conn = transport->transportConn;
  std::chrono::milliseconds interval(10);
  TestPingCallback pingCallback;
  auto transportSetPingCallback1 = transport->setPingCallback(&pingCallback);
  transport->invokeSendPing(interval);
  EXPECT_EQ(transport->isPingTimeoutScheduled(), true);
  EXPECT_EQ(conn->pendingEvents.cancelPingTimeout, false);
  conn->pendingEvents.cancelPingTimeout = true;
  transport->invokeHandlePingCallbacks();
  qEvb->loopOnce();
  EXPECT_EQ(transport->isPingTimeoutScheduled(), false);
  EXPECT_EQ(conn->pendingEvents.cancelPingTimeout, false);
}

TEST_P(QuicTransportImplTestBase, FailedPing) {
  auto conn = transport->transportConn;
  std::chrono::milliseconds interval(10);
  TestPingCallback pingCallback;
  auto transportSetPingCallback2 = transport->setPingCallback(&pingCallback);
  transport->invokeSendPing(interval);
  EXPECT_EQ(transport->isPingTimeoutScheduled(), true);
  EXPECT_EQ(conn->pendingEvents.cancelPingTimeout, false);
  conn->pendingEvents.cancelPingTimeout = true;
  transport->invokeCancelPingTimeout();
  transport->invokeHandlePingCallbacks();
  EXPECT_EQ(conn->pendingEvents.cancelPingTimeout, false);
}

TEST_P(QuicTransportImplTestBase, HandleKnobCallbacks) {
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
  BufPtr buf(folly::IOBuf::create(data.size()));
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
  qEvb->loopOnce();
  EXPECT_EQ(conn->pendingEvents.knobs.size(), 0);

  // detach the observer from the socket
  EXPECT_TRUE(transport->removeObserver(obs1.get()));
  EXPECT_TRUE(transport->removeObserver(obs2.get()));
  EXPECT_TRUE(transport->removeObserver(obs3.get()));
}

TEST_P(QuicTransportImplTestBase, StreamWriteCallbackUnregister) {
  auto stream = transport->createBidirectionalStream().value();
  // Unset before set
  EXPECT_FALSE(transport->unregisterStreamWriteCallback(stream));

  // Set
  auto wcb = std::make_unique<MockWriteCallback>();
  EXPECT_CALL(*wcb, onStreamWriteReady(stream, _)).Times(1);
  auto result = transport->notifyPendingWriteOnStream(stream, wcb.get());
  EXPECT_TRUE(result);
  qEvb->loopOnce();

  // Set then unset
  EXPECT_CALL(*wcb, onStreamWriteReady(stream, _)).Times(0);
  result = transport->notifyPendingWriteOnStream(stream, wcb.get());
  EXPECT_TRUE(result);
  EXPECT_TRUE(transport->unregisterStreamWriteCallback(stream));
  qEvb->loopOnce();

  // Set, close, unset
  result = transport->notifyPendingWriteOnStream(stream, wcb.get());
  EXPECT_TRUE(result);
  MockReadCallback rcb;
  ASSERT_FALSE(transport->setReadCallback(stream, &rcb).hasError());
  // ReadCallback kills WriteCallback
  EXPECT_CALL(rcb, readError(stream, _))
      .WillOnce(Invoke([&](StreamId stream, auto) {
        EXPECT_TRUE(transport->unregisterStreamWriteCallback(stream));
        wcb.reset();
      }));
  transport->close(std::nullopt);
  qEvb->loopOnce();
}

TEST_P(QuicTransportImplTestBase, ObserverRemove) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));
  EXPECT_CALL(*cb, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_P(QuicTransportImplTestBase, ObserverDestroy) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));
  InSequence s;
  EXPECT_CALL(*cb, closeStarted(transport.get(), _));
  EXPECT_CALL(*cb, closing(transport.get(), _));
  EXPECT_CALL(*cb, destroy(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_P(QuicTransportImplTestBase, ObserverRemoveMissing) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_FALSE(transport->removeObserver(cb.get()));
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_P(QuicTransportImplTestBase, ObserverSharedPtrRemove) {
  auto cb = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb);
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));
  EXPECT_CALL(*cb, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb));
  Mock::VerifyAndClearExpectations(cb.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_P(QuicTransportImplTestBase, ObserverSharedPtrDestroy) {
  auto cb = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb);
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));
  InSequence s;
  EXPECT_CALL(*cb, closeStarted(transport.get(), _));
  EXPECT_CALL(*cb, closing(transport.get(), _));
  EXPECT_CALL(*cb, destroy(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_P(QuicTransportImplTestBase, ObserverSharedPtrReleasedDestroy) {
  auto cb = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb);
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));

  // now that observer is attached, we release shared_ptr but keep raw ptr
  // since the container holds shared_ptr too, observer should not be destroyed
  MockLegacyObserver::Safety dc(*cb.get());
  auto cbRaw = cb.get();
  cb = nullptr;
  EXPECT_FALSE(dc.destroyed()); // should still exist

  InSequence s;
  EXPECT_CALL(*cbRaw, closeStarted(transport.get(), _));
  EXPECT_CALL(*cbRaw, closing(transport.get(), _));
  EXPECT_CALL(*cbRaw, destroy(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_P(QuicTransportImplTestBase, ObserverSharedPtrRemoveMissing) {
  auto cb = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_FALSE(transport->removeObserver(cb.get()));
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_P(QuicTransportImplTestBase, ObserverDetachImmediately) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));

  EXPECT_CALL(*cb, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_P(QuicTransportImplTestBase, ObserverDetachAfterClose) {
  // disable draining to ensure closing() event occurs immediately after close()
  {
    auto transportSettings = transport->getTransportSettings();
    transportSettings.shouldDrain = false;
    transport->setTransportSettings(transportSettings);
  }

  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));

  EXPECT_CALL(*cb, closeStarted(transport.get(), _));
  EXPECT_CALL(*cb, closing(transport.get(), _));
  transport->close(std::nullopt);
  Mock::VerifyAndClearExpectations(cb.get());

  EXPECT_CALL(*cb, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb.get()));
  Mock::VerifyAndClearExpectations(cb.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_F(QuicTransportImplTest, ObserverDetachOnCloseStartedDuringDestroy) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));

  InSequence s;

  EXPECT_CALL(*cb, closeStarted(transport.get(), _))
      .WillOnce(Invoke([&cb](auto callbackTransport, auto /* errorOpt */) {
        EXPECT_TRUE(callbackTransport->removeObserver(cb.get()));
      }));
  EXPECT_CALL(*cb, observerDetach(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_F(QuicTransportImplTest, ObserverDetachOnClosingDuringDestroy) {
  auto cb = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb, observerAttach(transport.get()));
  transport->addObserver(cb.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb.get()));

  InSequence s;

  EXPECT_CALL(*cb, closeStarted(transport.get(), _));
  EXPECT_CALL(*cb, closing(transport.get(), _))
      .WillOnce(Invoke([&cb](auto callbackTransport, auto /* errorOpt */) {
        EXPECT_TRUE(callbackTransport->removeObserver(cb.get()));
      }));
  EXPECT_CALL(*cb, observerDetach(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb.get());
}

TEST_P(QuicTransportImplTestBase, ObserverMultipleAttachRemove) {
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

TEST_P(QuicTransportImplTestBase, ObserverSharedPtrMultipleAttachRemove) {
  auto cb1 = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb1, observerAttach(transport.get()));
  transport->addObserver(cb1);
  Mock::VerifyAndClearExpectations(cb1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb1.get()));

  auto cb2 = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*cb2, observerAttach(transport.get()));
  transport->addObserver(cb2);
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_THAT(
      transport->getObservers(), UnorderedElementsAre(cb1.get(), cb2.get()));

  EXPECT_CALL(*cb1, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb1));
  Mock::VerifyAndClearExpectations(cb1.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb2.get()));

  EXPECT_CALL(*cb2, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb2));
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_P(QuicTransportImplTestBase, ObserverMultipleAttachRemoveReverse) {
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
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(cb1.get()));

  EXPECT_CALL(*cb1, observerDetach(transport.get()));
  EXPECT_TRUE(transport->removeObserver(cb1.get()));
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TEST_P(QuicTransportImplTestBase, ObserverMultipleAttachDestroy) {
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
  EXPECT_CALL(*cb1, closeStarted(transport.get(), _));
  EXPECT_CALL(*cb2, closeStarted(transport.get(), _));
  EXPECT_CALL(*cb1, closing(transport.get(), _));
  EXPECT_CALL(*cb2, closing(transport.get(), _));
  EXPECT_CALL(*cb1, destroy(transport.get()));
  EXPECT_CALL(*cb2, destroy(transport.get()));
  transport = nullptr;
  Mock::VerifyAndClearExpectations(cb1.get());
  Mock::VerifyAndClearExpectations(cb2.get());
}

TEST_P(QuicTransportImplTestBase, ObserverDetachAndAttachEvb) {
  LegacyObserver::EventSet eventSet;
  eventSet.enable(SocketObserverInterface::Events::evbEvents);

  auto obs1 = std::make_unique<NiceMock<MockLegacyObserver>>();
  auto obs2 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  auto obs3 = std::make_unique<NiceMock<MockLegacyObserver>>(eventSet);
  transport->addObserver(obs1.get());
  transport->addObserver(obs2.get());
  transport->addObserver(obs3.get());

  // check the current event base and create a new one
  EXPECT_EQ(qEvb, transport->getEventBase());

  folly::EventBase fEvb2;
  std::shared_ptr<QuicEventBase> qEvb2 =
      std::make_shared<FollyQuicEventBase>(&fEvb2);

  // Detach the event base evb
  EXPECT_CALL(*obs1, evbDetach(transport.get(), qEvb.get())).Times(0);
  EXPECT_CALL(*obs2, evbDetach(transport.get(), qEvb.get())).Times(1);
  EXPECT_CALL(*obs3, evbDetach(transport.get(), qEvb.get())).Times(1);
  transport->detachEventBase();
  EXPECT_EQ(nullptr, transport->getEventBase());

  // Attach a new event base evb2
  EXPECT_CALL(*obs1, evbAttach(transport.get(), qEvb2.get())).Times(0);
  EXPECT_CALL(*obs2, evbAttach(transport.get(), qEvb2.get())).Times(1);
  EXPECT_CALL(*obs3, evbAttach(transport.get(), qEvb2.get())).Times(1);
  transport->attachEventBase(qEvb2);
  EXPECT_EQ(qEvb2, transport->getEventBase());

  // Detach the event base evb2
  EXPECT_CALL(*obs1, evbDetach(transport.get(), qEvb2.get())).Times(0);
  EXPECT_CALL(*obs2, evbDetach(transport.get(), qEvb2.get())).Times(1);
  EXPECT_CALL(*obs3, evbDetach(transport.get(), qEvb2.get())).Times(1);
  transport->detachEventBase();
  EXPECT_EQ(nullptr, transport->getEventBase());

  // Attach the original event base evb
  EXPECT_CALL(*obs1, evbAttach(transport.get(), qEvb.get())).Times(0);
  EXPECT_CALL(*obs2, evbAttach(transport.get(), qEvb.get())).Times(1);
  EXPECT_CALL(*obs3, evbAttach(transport.get(), qEvb.get())).Times(1);
  transport->attachEventBase(qEvb);
  EXPECT_EQ(qEvb, transport->getEventBase());

  EXPECT_TRUE(transport->removeObserver(obs1.get()));
  EXPECT_TRUE(transport->removeObserver(obs2.get()));
  EXPECT_TRUE(transport->removeObserver(obs3.get()));
}

TEST_P(QuicTransportImplTestBase, GetConnectionStatsSmoke) {
  auto stats = transport->getConnectionsStats();
  EXPECT_EQ(stats.congestionController, CongestionControlType::Cubic);
  EXPECT_EQ(stats.clientConnectionId, "0a090807");
}

TEST_P(QuicTransportImplTestBase, DatagramCallbackDatagramAvailable) {
  NiceMock<MockDatagramCallback> datagramCb;
  transport->enableDatagram();
  auto transportSetDatagramCallback1 =
      transport->setDatagramCallback(&datagramCb);
  transport->addDatagram(folly::IOBuf::copyBuffer("datagram payload"));
  EXPECT_CALL(datagramCb, onDatagramsAvailable());
  transport->driveReadCallbacks();
}

TEST_P(QuicTransportImplTestBase, ZeroLengthDatagram) {
  NiceMock<MockDatagramCallback> datagramCb;
  transport->enableDatagram();
  auto transportSetDatagramCallback2 =
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

TEST_P(QuicTransportImplTestBase, ZeroLengthDatagramBufs) {
  NiceMock<MockDatagramCallback> datagramCb;
  transport->enableDatagram();
  auto transportSetDatagramCallback3 =
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

TEST_P(QuicTransportImplTestBase, Cmsgs) {
  transport->setServerConnectionId();
  folly::SocketCmsgMap cmsgs;
  cmsgs[{IPPROTO_IP, IP_TOS}] = 123;
  EXPECT_CALL(*socketPtr, setCmsgs(_)).Times(1);
  transport->setCmsgs(cmsgs);

  EXPECT_CALL(*socketPtr, appendCmsgs(_)).Times(1);
  transport->appendCmsgs(cmsgs);
}

class QuicTransportImplTestCounters : public QuicTransportImplTest {};

TEST_F(QuicTransportImplTestCounters, TransportResetClosesStreams) {
  MockQuicStats quicStats;
  auto transportSettings = transport->getTransportSettings();
  auto& conn = transport->getConnectionState();
  conn.statsCallback = &quicStats;

  EXPECT_CALL(quicStats, onNewQuicStream()).Times(2);
  EXPECT_CALL(quicStats, onQuicStreamClosed()).Times(2);

  auto stream1 = transport->createBidirectionalStream().value();
  auto stream2 = transport->createBidirectionalStream().value();

  EXPECT_EQ(stream1, 1);
  EXPECT_EQ(stream2, 5);
  EXPECT_EQ(conn.streamManager->streamCount(), 2);
  transport.reset();
}

class QuicTransportImplTestWithGroups : public QuicTransportImplTestBase {};

INSTANTIATE_TEST_SUITE_P(
    QuicTransportImplTestWithGroups,
    QuicTransportImplTestWithGroups,
    ::testing::Values(DelayedStreamNotifsTestParam{true}));

TEST_P(QuicTransportImplTestWithGroups, ReadCallbackWithGroupsDataAvailable) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.advertisedMaxStreamGroups = 16;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  auto groupId = transport->createBidirectionalStreamGroup();
  EXPECT_TRUE(groupId.has_value());
  auto stream1 = transport->createBidirectionalStreamInGroup(*groupId).value();
  auto stream2 = transport->createBidirectionalStreamInGroup(*groupId).value();

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());
  ASSERT_FALSE(transport->setReadCallback(stream2, &readCb2).hasError());

  transport->addDataToStream(
      stream1,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0),
      *groupId);

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10),
      *groupId);

  EXPECT_CALL(readCb1, readAvailableWithGroup(stream1, *groupId));
  transport->driveReadCallbacks();

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0),
      *groupId);

  EXPECT_CALL(readCb1, readAvailableWithGroup(stream1, *groupId));
  EXPECT_CALL(readCb2, readAvailableWithGroup(stream2, *groupId));
  transport->driveReadCallbacks();

  EXPECT_CALL(readCb1, readAvailableWithGroup(stream1, *groupId));
  EXPECT_CALL(readCb2, readAvailableWithGroup(stream2, *groupId));
  transport->driveReadCallbacks();

  EXPECT_CALL(readCb2, readAvailableWithGroup(stream2, *groupId));
  ASSERT_FALSE(transport->setReadCallback(stream1, nullptr).hasError());
  transport->driveReadCallbacks();
  transport.reset();
}

TEST_P(QuicTransportImplTestWithGroups, ReadErrorCallbackWithGroups) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.advertisedMaxStreamGroups = 16;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  auto groupId = transport->createBidirectionalStreamGroup();
  EXPECT_TRUE(groupId.has_value());
  auto stream1 = transport->createBidirectionalStreamInGroup(*groupId).value();

  NiceMock<MockReadCallback> readCb1;

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());

  transport->addStreamReadError(stream1, LocalErrorCode::NO_ERROR);
  transport->addDataToStream(
      stream1,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0),
      *groupId);

  EXPECT_CALL(readCb1, readErrorWithGroup(stream1, *groupId, _));
  transport->driveReadCallbacks();

  transport.reset();
}

TEST_P(
    QuicTransportImplTestWithGroups,
    ReadCallbackWithGroupsCancellCallbacks) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.advertisedMaxStreamGroups = 16;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  auto groupId = transport->createBidirectionalStreamGroup();
  EXPECT_TRUE(groupId.has_value());
  auto stream1 = transport->createBidirectionalStreamInGroup(*groupId).value();
  auto stream2 = transport->createBidirectionalStreamInGroup(*groupId).value();

  NiceMock<MockReadCallback> readCb1;
  NiceMock<MockReadCallback> readCb2;

  ASSERT_FALSE(transport->setReadCallback(stream1, &readCb1).hasError());
  ASSERT_FALSE(transport->setReadCallback(stream2, &readCb2).hasError());

  transport->addDataToStream(
      stream1,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 0),
      *groupId);

  transport->addDataToStream(
      stream2,
      StreamBuffer(folly::IOBuf::copyBuffer("actual stream data"), 10),
      *groupId);

  EXPECT_CALL(readCb1, readErrorWithGroup(stream1, *groupId, _));
  EXPECT_CALL(readCb2, readErrorWithGroup(stream2, *groupId, _));
  QuicError error =
      QuicError(TransportErrorCode::PROTOCOL_VIOLATION, "test error");
  transport->cancelAllAppCallbacks(error);
  transport.reset();
}

TEST_P(QuicTransportImplTestWithGroups, onNewStreamsAndGroupsCallbacks) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.advertisedMaxStreamGroups = 16;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  auto readData = folly::IOBuf::copyBuffer("actual stream data");

  StreamGroupId groupId = 0x00;
  StreamId stream1 = 0x00;
  EXPECT_CALL(connCallback, onNewBidirectionalStreamGroup(groupId));
  EXPECT_CALL(connCallback, onNewBidirectionalStreamInGroup(stream1, groupId));
  transport->addDataToStream(
      stream1, StreamBuffer(readData->clone(), 0, true), groupId);

  StreamId stream2 = 0x04;
  EXPECT_CALL(connCallback, onNewBidirectionalStreamInGroup(stream2, groupId));
  transport->addDataToStream(
      stream2, StreamBuffer(readData->clone(), 0, true), groupId);

  StreamGroupId groupIdUni = 0x02;
  StreamId uniStream3 = 0xa;
  EXPECT_CALL(connCallback, onNewUnidirectionalStreamGroup(groupIdUni));
  EXPECT_CALL(
      connCallback, onNewUnidirectionalStreamInGroup(uniStream3, groupIdUni));
  transport->addDataToStream(
      uniStream3, StreamBuffer(readData->clone(), 0, true), groupIdUni);

  transport.reset();
}

TEST_P(
    QuicTransportImplTestWithGroups,
    TestSetStreamGroupRetransmissionPolicyAllowed) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.advertisedMaxStreamGroups = 16;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  const StreamGroupId groupId = 0x00;
  const QuicStreamGroupRetransmissionPolicy policy;

  // Test policy set allowed
  auto res = transport->setStreamGroupRetransmissionPolicy(groupId, policy);
  EXPECT_TRUE(res.has_value());

  // Test policy set not allowed.
  transportSettings.advertisedMaxStreamGroups = 0;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());
  res = transport->setStreamGroupRetransmissionPolicy(groupId, policy);
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error(), LocalErrorCode::INVALID_OPERATION);
  EXPECT_EQ(1, transport->getStreamGroupRetransmissionPolicies().size());

  transport.reset();
}

TEST_P(
    QuicTransportImplTestWithGroups,
    TestStreamGroupRetransmissionPolicyReset) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.advertisedMaxStreamGroups = 16;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  const StreamGroupId groupId = 0x00;
  QuicStreamGroupRetransmissionPolicy policy;

  // Add the policy.
  auto res = transport->setStreamGroupRetransmissionPolicy(groupId, policy);
  EXPECT_TRUE(res.has_value());
  EXPECT_EQ(transport->getStreamGroupRetransmissionPolicies().size(), 1);

  // Reset allowed.
  res = transport->setStreamGroupRetransmissionPolicy(groupId, std::nullopt);
  EXPECT_TRUE(res.has_value());
  EXPECT_EQ(transport->getStreamGroupRetransmissionPolicies().size(), 0);

  // Add the policy back.
  res = transport->setStreamGroupRetransmissionPolicy(groupId, policy);
  EXPECT_TRUE(res.has_value());
  EXPECT_EQ(transport->getStreamGroupRetransmissionPolicies().size(), 1);

  // Reset allowed even if custom policies are disabled.
  transportSettings.advertisedMaxStreamGroups = 0;
  res = transport->setStreamGroupRetransmissionPolicy(groupId, std::nullopt);
  EXPECT_TRUE(res.has_value());
  EXPECT_EQ(transport->getStreamGroupRetransmissionPolicies().size(), 0);

  transport.reset();
}

TEST_P(
    QuicTransportImplTestWithGroups,
    TestStreamGroupRetransmissionPolicyAddRemove) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.advertisedMaxStreamGroups = 16;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  // Add a policy.
  const StreamGroupId groupId = 0x00;
  const QuicStreamGroupRetransmissionPolicy policy;
  auto res = transport->setStreamGroupRetransmissionPolicy(groupId, policy);
  EXPECT_TRUE(res.has_value());
  EXPECT_EQ(transport->getStreamGroupRetransmissionPolicies().size(), 1);

  // Add another one.
  const StreamGroupId groupId2 = 0x04;
  const QuicStreamGroupRetransmissionPolicy policy2;
  res = transport->setStreamGroupRetransmissionPolicy(groupId2, policy2);
  EXPECT_TRUE(res.has_value());
  EXPECT_EQ(transport->getStreamGroupRetransmissionPolicies().size(), 2);

  // Remove second policy.
  res = transport->setStreamGroupRetransmissionPolicy(groupId2, std::nullopt);
  EXPECT_TRUE(res.has_value());
  EXPECT_EQ(transport->getStreamGroupRetransmissionPolicies().size(), 1);

  // Remove first policy.
  res = transport->setStreamGroupRetransmissionPolicy(groupId, std::nullopt);
  EXPECT_TRUE(res.has_value());
  EXPECT_EQ(transport->getStreamGroupRetransmissionPolicies().size(), 0);

  transport.reset();
}

TEST_P(
    QuicTransportImplTestWithGroups,
    TestStreamGroupRetransmissionPolicyMaxLimit) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.advertisedMaxStreamGroups = 1;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  // Add a policy.
  const StreamGroupId groupId = 0x00;
  const QuicStreamGroupRetransmissionPolicy policy;
  auto res = transport->setStreamGroupRetransmissionPolicy(groupId, policy);
  EXPECT_TRUE(res.has_value());
  EXPECT_EQ(transport->getStreamGroupRetransmissionPolicies().size(), 1);

  // Try adding another one; should be over the limit.
  const StreamGroupId groupId2 = 0x04;
  res = transport->setStreamGroupRetransmissionPolicy(groupId2, policy);
  EXPECT_TRUE(res.hasError());
  EXPECT_EQ(res.error(), LocalErrorCode::RTX_POLICIES_LIMIT_EXCEEDED);
  EXPECT_EQ(transport->getStreamGroupRetransmissionPolicies().size(), 1);

  transport.reset();
}

TEST_P(QuicTransportImplTestBase, TestUpdateWriteLooperWithWritableCallback) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.useSockWritableEvents = true;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  EXPECT_CALL(*socketPtr, isWritableCallbackSet()).WillOnce(Return(true));
  transport->updateWriteLooper(true /* thisIteration */);

  // Disable useSockWritableEvents.
  transportSettings = transport->getTransportSettings();
  transportSettings.useSockWritableEvents = false;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  EXPECT_CALL(*socketPtr, isWritableCallbackSet()).Times(0);
  transport->updateWriteLooper(true /* thisIteration */);

  transport.reset();
}

TEST_P(
    QuicTransportImplTestBase,
    TestMaybeStopWriteLooperAndArmSocketWritableEvent) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.useSockWritableEvents = true;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();

  // Create a stream with outgoing data.
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);
  auto dataBuf = IOBuf::copyBuffer("hello");
  stream->pendingWrites.append(dataBuf);
  stream->writeBuffer.append(std::move(dataBuf));

  // Insert streamId into the list.
  conn->streamManager->updateWritableStreams(*stream);

  // Write looper is running.
  transport->writeLooper()->run(true /* thisIteration */);
  EXPECT_TRUE(transport->writeLooper()->isRunning());

  // Write event is not armed.
  EXPECT_CALL(*socketPtr, isWritableCallbackSet()).WillOnce(Return(false));
  EXPECT_CALL(*socketPtr, resumeWrite(_))
      .WillOnce(Return(quic::Expected<void, QuicError>{}));
  transport->maybeStopWriteLooperAndArmSocketWritableEvent();
  // Write looper is stopped.
  EXPECT_FALSE(transport->writeLooper()->isRunning());

  transport.reset();
}

TEST_P(
    QuicTransportImplTestBase,
    TestMaybeStopWriteLooperAndArmSocketWritableEventNoData) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.useSockWritableEvents = true;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();

  // Write looper is running.
  transport->writeLooper()->run(true /* thisIteration */);
  EXPECT_TRUE(transport->writeLooper()->isRunning());

  // Write event is not armed.
  EXPECT_CALL(*socketPtr, isWritableCallbackSet()).WillOnce(Return(false));
  EXPECT_CALL(*socketPtr, resumeWrite(_)).Times(0);
  transport->maybeStopWriteLooperAndArmSocketWritableEvent();
  // Write looper is still running.
  EXPECT_TRUE(transport->writeLooper()->isRunning());

  transport.reset();
}

TEST_P(
    QuicTransportImplTestBase,
    TestMaybeStopWriteLooperAndArmSocketWritableEventAlreadyArmed) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.useSockWritableEvents = true;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();

  // Create a stream with outgoing data.
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);
  auto dataBuf = IOBuf::copyBuffer("hello");
  stream->pendingWrites.append(dataBuf);
  stream->writeBuffer.append(std::move(dataBuf));

  // Insert streamId into the list.
  conn->streamManager->updateWritableStreams(*stream);

  // Write looper is stopped.
  EXPECT_FALSE(transport->writeLooper()->isRunning());

  // Write event is already armed.
  EXPECT_CALL(*socketPtr, isWritableCallbackSet()).WillOnce(Return(true));
  EXPECT_CALL(*socketPtr, resumeWrite(_)).Times(0);
  transport->maybeStopWriteLooperAndArmSocketWritableEvent();
  // Write looper is still stopped.
  EXPECT_FALSE(transport->writeLooper()->isRunning());

  transport.reset();
}

TEST_P(
    QuicTransportImplTestBase,
    TestMaybeStopWriteLooperAndArmSocketWritableEventNoCongestionControlAvailable) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.useSockWritableEvents = true;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();

  // Create a stream with outgoing data.
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);
  auto dataBuf = IOBuf::copyBuffer("hello");
  stream->pendingWrites.append(dataBuf);
  stream->writeBuffer.append(std::move(dataBuf));

  // Insert streamId into the list.
  conn->streamManager->updateWritableStreams(*stream);

  // Write looper is running.
  transport->writeLooper()->run(true /* thisIteration */);
  EXPECT_TRUE(transport->writeLooper()->isRunning());

  // Fake in-flight bytes for CC to return no window available.
  conn->lossState.inflightBytes = 123234534;

  // Write event is not armed.
  EXPECT_CALL(*socketPtr, isWritableCallbackSet()).WillOnce(Return(false));
  EXPECT_CALL(*socketPtr, resumeWrite(_)).Times(0);
  transport->maybeStopWriteLooperAndArmSocketWritableEvent();
  // Write looper is still running.
  EXPECT_TRUE(transport->writeLooper()->isRunning());

  transport.reset();
}

TEST_P(
    QuicTransportImplTestBase,
    TestMaybeStopWriteLooperAndArmSocketWritableEventNoFlowControlAvailable) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.useSockWritableEvents = true;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();

  // Create a stream with outgoing data.
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);
  auto dataBuf = IOBuf::copyBuffer("hello");
  stream->pendingWrites.append(dataBuf);
  stream->writeBuffer.append(std::move(dataBuf));

  // Insert streamId into the list.
  conn->streamManager->updateWritableStreams(*stream);

  // Write looper is running.
  transport->writeLooper()->run(true /* thisIteration */);
  EXPECT_TRUE(transport->writeLooper()->isRunning());

  // Fake no flow control.
  conn->flowControlState.peerAdvertisedMaxOffset =
      conn->flowControlState.sumCurWriteOffset = 1024;

  // Write event is not armed.
  EXPECT_CALL(*socketPtr, isWritableCallbackSet()).WillOnce(Return(false));
  EXPECT_CALL(*socketPtr, resumeWrite(_)).Times(0);
  transport->maybeStopWriteLooperAndArmSocketWritableEvent();
  // Write looper is still running.
  EXPECT_TRUE(transport->writeLooper()->isRunning());

  transport.reset();
}

TEST_P(QuicTransportImplTestBase, TestOnSocketWritable) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.useSockWritableEvents = true;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  // Write looper is not running.
  EXPECT_FALSE(transport->writeLooper()->isRunning());

  EXPECT_CALL(*socketPtr, pauseWrite()).Times(1);
  transport->onSocketWritable();

  // Write looper is running.
  EXPECT_TRUE(transport->writeLooper()->isRunning());

  transport.reset();
}

TEST_P(
    QuicTransportImplTestBase,
    TestBackpressureWriterArmsSocketWritableEvent) {
  transport->setServerConnectionId();
  auto transportSettings = transport->getTransportSettings();

  transportSettings.useSockWritableEvents = true;
  transportSettings.batchingMode = QuicBatchingMode::BATCHING_MODE_NONE;
  transportSettings.maxBatchSize = 1;
  transportSettings.dataPathType = DataPathType::ChainedMemory;
  transportSettings.enableWriterBackpressure = true;

  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();

  // Create a stream with outgoing data.
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);
  std::string testString = "hello";
  auto dataBuf = IOBuf::copyBuffer(testString);
  stream->pendingWrites.append(dataBuf);
  stream->writeBuffer.append(std::move(dataBuf));
  conn->flowControlState.sumCurStreamBufferLen = testString.length();

  // Insert streamId into the list.
  conn->streamManager->updateWritableStreams(*stream);

  // Mock arming the write callback
  bool writeCallbackArmed = false;
  EXPECT_CALL(*socketPtr, isWritableCallbackSet()).WillRepeatedly(Invoke([&]() {
    return writeCallbackArmed;
  }));
  EXPECT_CALL(*socketPtr, resumeWrite(_))
      .WillOnce(Invoke(
          [&](QuicAsyncUDPSocket::WriteCallback*)
              -> quic::Expected<void, QuicError> {
            writeCallbackArmed = true;
            return {};
          }));

  // Fail the first write loop.
  EXPECT_CALL(*socketPtr, write(_, _, _))
      .Times(2) // We attempt to flush the batch twice inside the write loop.
                // Fail both.
      .WillRepeatedly(
          Invoke([&](const folly::SocketAddress&, const struct iovec*, size_t) {
            errno = EAGAIN;
            return 0;
          }));

  transport->writeLooper()->run(true /* thisIteration */);
  EXPECT_TRUE(transport->writeLooper()->isRunning());

  // A write attempt will cache the failed write, stop the write looper, and arm
  // the write callback.
  transport->pacedWriteDataToSocketThroughTransportBase();

  // The transport has cached the failed write buffer.
  EXPECT_TRUE(conn->pendingWriteBatch_.buf);
  // Write looper stopped.
  EXPECT_FALSE(transport->writeLooper()->isRunning());
  // Write callback armed.
  EXPECT_TRUE(writeCallbackArmed);

  // Reset will make one write attempt. We don't care what happens to it
  EXPECT_CALL(*socketPtr, write(_, _, _))
      .Times(1)
      .WillRepeatedly(Invoke([&](const folly::SocketAddress&,
                                 const struct iovec* vec,
                                 size_t iovec_len) {
        errno = 0;
        return getTotalIovecLen(vec, iovec_len);
      }));
  transport.reset();
}

TEST_P(
    QuicTransportImplTestBase,
    TestMaybeStopWriteLooperAndArmSocketWritableEventOnClosedSocket) {
  auto transportSettings = transport->getTransportSettings();
  transportSettings.useSockWritableEvents = true;
  transport->setTransportSettings(transportSettings);
  ASSERT_FALSE(transport->getConnectionState()
                   .streamManager->refreshTransportSettings(transportSettings)
                   .hasError());

  transport->transportConn->oneRttWriteCipher = test::createNoOpAead();

  // Create a stream with outgoing data.
  auto streamId = transport->createBidirectionalStream().value();
  const auto& conn = transport->transportConn;
  auto stream = transport->getStream(streamId);
  auto dataBuf = IOBuf::copyBuffer("hello");
  stream->pendingWrites.append(dataBuf);
  stream->writeBuffer.append(std::move(dataBuf));

  // Insert streamId into the list.
  conn->streamManager->updateWritableStreams(*stream);

  // Write looper is running.
  transport->writeLooper()->run(true /* thisIteration */);
  EXPECT_TRUE(transport->writeLooper()->isRunning());

  // Close the socket.
  transport->closeImpl((QuicError(
      QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
      std::string("writeSocketDataAndCatch()  error"))));
  transport->maybeStopWriteLooperAndArmSocketWritableEvent();

  transport.reset();
}

} // namespace quic::test
