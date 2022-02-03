/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>

#include <quic/api/QuicSocket.h>

namespace quic {

class MockQuicSocket : public QuicSocket {
 public:
  using SharedBuf = std::shared_ptr<folly::IOBuf>;

  MockQuicSocket(
      folly::EventBase* /*eventBase*/,
      ConnectionSetupCallback* setupCb,
      ConnectionCallbackNew* connCb)
      : setupCb_(setupCb), connCb_(connCb) {}

  MOCK_CONST_METHOD0(good, bool());
  MOCK_CONST_METHOD0(replaySafe, bool());
  MOCK_CONST_METHOD0(error, bool());
  MOCK_METHOD1(
      close,
      void(folly::Optional<std::pair<QuicErrorCode, std::string>>));
  MOCK_METHOD0(closeGracefully, void());
  MOCK_METHOD1(
      closeNow,
      void(folly::Optional<std::pair<QuicErrorCode, std::string>>));
  MOCK_CONST_METHOD0(
      getClientConnectionId,
      folly::Optional<quic::ConnectionId>());
  MOCK_CONST_METHOD0(getTransportSettings, const TransportSettings&());
  MOCK_CONST_METHOD0(
      getServerConnectionId,
      folly::Optional<quic::ConnectionId>());
  MOCK_CONST_METHOD0(
      getClientChosenDestConnectionId,
      folly::Optional<quic::ConnectionId>());
  MOCK_CONST_METHOD0(getPeerAddress, const folly::SocketAddress&());
  MOCK_CONST_METHOD0(getOriginalPeerAddress, const folly::SocketAddress&());
  MOCK_CONST_METHOD0(getLocalAddress, const folly::SocketAddress&());
  MOCK_CONST_METHOD0(getEventBase, folly::EventBase*());
  MOCK_CONST_METHOD1(
      getStreamReadOffset,
      folly::Expected<size_t, LocalErrorCode>(StreamId));
  MOCK_CONST_METHOD1(
      getStreamWriteOffset,
      folly::Expected<size_t, LocalErrorCode>(StreamId));
  MOCK_CONST_METHOD1(
      getStreamWriteBufferedBytes,
      folly::Expected<size_t, LocalErrorCode>(StreamId));
  MOCK_CONST_METHOD0(getTransportInfo, QuicSocket::TransportInfo());
  MOCK_CONST_METHOD1(
      getStreamTransportInfo,
      folly::Expected<QuicSocket::StreamTransportInfo, LocalErrorCode>(
          StreamId));
  MOCK_CONST_METHOD0(getAppProtocol, folly::Optional<std::string>());
  MOCK_METHOD2(setReceiveWindow, void(StreamId, size_t));
  MOCK_METHOD3(setSendBuffer, void(StreamId, size_t, size_t));
  MOCK_CONST_METHOD0(getConnectionBufferAvailable, uint64_t());
  MOCK_CONST_METHOD0(
      getConnectionFlowControl,
      folly::Expected<FlowControlState, LocalErrorCode>());
  MOCK_CONST_METHOD1(
      getStreamFlowControl,
      folly::Expected<FlowControlState, LocalErrorCode>(StreamId));
  MOCK_METHOD0(unsetAllReadCallbacks, void());
  MOCK_METHOD0(unsetAllPeekCallbacks, void());
  MOCK_METHOD0(unsetAllDeliveryCallbacks, void());
  MOCK_METHOD1(cancelDeliveryCallbacksForStream, void(StreamId));
  MOCK_METHOD2(
      cancelDeliveryCallbacksForStream,
      void(StreamId, uint64_t offset));
  MOCK_METHOD1(
      setConnectionFlowControlWindow,
      folly::Expected<folly::Unit, LocalErrorCode>(uint64_t));
  MOCK_METHOD2(
      setStreamFlowControlWindow,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId, uint64_t));
  MOCK_METHOD1(setTransportSettings, void(TransportSettings));
  MOCK_METHOD1(
      setMaxPacingRate,
      folly::Expected<folly::Unit, LocalErrorCode>(uint64_t));
  folly::Expected<folly::Unit, LocalErrorCode>
  setKnob(uint64_t knobSpace, uint64_t knobId, Buf knobBlob) override {
    SharedBuf sharedBlob(knobBlob.release());
    return setKnob(knobSpace, knobId, sharedBlob);
  }
  MOCK_METHOD3(
      setKnob,
      folly::Expected<folly::Unit, LocalErrorCode>(
          uint64_t,
          uint64_t,
          SharedBuf));
  MOCK_CONST_METHOD0(isKnobSupported, bool());
  MOCK_METHOD3(
      setStreamPriority,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId, uint8_t, bool));
  MOCK_METHOD1(
      getStreamPriority,
      folly::Expected<Priority, LocalErrorCode>(StreamId));
  MOCK_METHOD3(
      setReadCallback,
      folly::Expected<folly::Unit, LocalErrorCode>(
          StreamId,
          ReadCallback*,
          folly::Optional<ApplicationErrorCode> err));
  MOCK_METHOD1(setConnectionSetupCallback, void(ConnectionSetupCallback*));
  MOCK_METHOD1(setConnectionCallbackNew, void(ConnectionCallbackNew*));
  void setEarlyDataAppParamsFunctions(
      folly::Function<bool(const folly::Optional<std::string>&, const Buf&)
                          const> validator,
      folly::Function<Buf()> getter) override {
    earlyDataAppParamsValidator_ = std::move(validator);
    earlyDataAppParamsGetter_ = std::move(getter);
  }
  MOCK_METHOD1(
      pauseRead,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId));
  MOCK_METHOD1(
      resumeRead,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId));
  MOCK_METHOD2(
      stopSending,
      folly::Expected<folly::Unit, LocalErrorCode>(
          StreamId,
          ApplicationErrorCode));
  folly::Expected<std::pair<Buf, bool>, LocalErrorCode> read(
      StreamId id,
      size_t maxRead) override {
    auto res = readNaked(id, maxRead);
    if (res.hasError()) {
      return folly::makeUnexpected(res.error());
    } else {
      return std::pair<Buf, bool>(Buf(res.value().first), res.value().second);
    }
  }
  using ReadResult =
      folly::Expected<std::pair<folly::IOBuf*, bool>, LocalErrorCode>;
  MOCK_METHOD2(readNaked, ReadResult(StreamId, size_t));
  MOCK_METHOD1(
      createBidirectionalStream,
      folly::Expected<StreamId, LocalErrorCode>(bool));
  MOCK_METHOD1(
      createUnidirectionalStream,
      folly::Expected<StreamId, LocalErrorCode>(bool));
  MOCK_CONST_METHOD0(getNumOpenableBidirectionalStreams, uint64_t());
  MOCK_CONST_METHOD0(getNumOpenableUnidirectionalStreams, uint64_t());
  GMOCK_METHOD1_(, noexcept, , isClientStream, bool(StreamId));
  GMOCK_METHOD1_(, noexcept, , isServerStream, bool(StreamId));
  GMOCK_METHOD1_(, noexcept, , getStreamInitiator, StreamInitiator(StreamId));
  GMOCK_METHOD1_(, noexcept, , isBidirectionalStream, bool(StreamId));
  GMOCK_METHOD1_(, noexcept, , isUnidirectionalStream, bool(StreamId));
  GMOCK_METHOD1_(
      ,
      noexcept,
      ,
      getStreamDirectionality,
      StreamDirectionality(StreamId));
  MOCK_METHOD1(
      notifyPendingWriteOnConnection,
      folly::Expected<folly::Unit, LocalErrorCode>(WriteCallback*));
  MOCK_METHOD2(
      notifyPendingWriteOnStream,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId, WriteCallback*));
  MOCK_METHOD1(
      unregisterStreamWriteCallback,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId));
  MOCK_METHOD3(
      registerTxCallback,
      folly::Expected<folly::Unit, LocalErrorCode>(
          const StreamId,
          const uint64_t,
          ByteEventCallback*));
  MOCK_METHOD4(
      registerByteEventCallback,
      folly::Expected<folly::Unit, LocalErrorCode>(
          const ByteEvent::Type,
          const StreamId,
          const uint64_t,
          ByteEventCallback*));
  MOCK_METHOD2(
      cancelByteEventCallbacksForStream,
      void(const StreamId id, const folly::Optional<uint64_t>& offset));
  MOCK_METHOD3(
      cancelByteEventCallbacksForStream,
      void(
          const ByteEvent::Type,
          const StreamId id,
          const folly::Optional<uint64_t>& offset));
  MOCK_METHOD0(cancelAllByteEventCallbacks, void());
  MOCK_METHOD1(cancelByteEventCallbacks, void(const ByteEvent::Type));
  MOCK_CONST_METHOD1(
      getNumByteEventCallbacksForStream,
      size_t(const StreamId id));
  MOCK_CONST_METHOD2(
      getNumByteEventCallbacksForStream,
      size_t(const ByteEvent::Type, const StreamId));
  folly::Expected<folly::Unit, LocalErrorCode>
  writeChain(StreamId id, Buf data, bool eof, ByteEventCallback* cb) override {
    SharedBuf sharedData(data.release());
    return writeChain(id, sharedData, eof, cb);
  }
  MOCK_METHOD4(
      writeChain,
      WriteResult(StreamId, SharedBuf, bool, ByteEventCallback*));
  MOCK_METHOD4(
      writeBufMeta,
      WriteResult(StreamId, const BufferMeta&, bool, ByteEventCallback*));
  MOCK_METHOD2(
      setDSRPacketizationRequestSenderRef,
      WriteResult(
          StreamId,
          const std::unique_ptr<DSRPacketizationRequestSender>&));
  WriteResult setDSRPacketizationRequestSender(
      StreamId streamId,
      std::unique_ptr<DSRPacketizationRequestSender> sender) override {
    return setDSRPacketizationRequestSenderRef(streamId, sender);
  }
  MOCK_METHOD3(
      registerDeliveryCallback,
      folly::Expected<folly::Unit, LocalErrorCode>(
          StreamId,
          uint64_t,
          ByteEventCallback*));

  MOCK_METHOD1(shutdownWrite, folly::Optional<LocalErrorCode>(StreamId));
  MOCK_METHOD2(
      resetStream,
      folly::Expected<folly::Unit, LocalErrorCode>(
          StreamId,
          ApplicationErrorCode));
  MOCK_METHOD2(
      maybeResetStreamFromReadError,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId, QuicErrorCode));
  MOCK_METHOD1(
      setPingCallback,
      folly::Expected<folly::Unit, LocalErrorCode>(PingCallback*));
  MOCK_METHOD1(sendPing, void(std::chrono::milliseconds));
  MOCK_CONST_METHOD0(getState, const QuicConnectionStateBase*());
  MOCK_METHOD0(isDetachable, bool());
  MOCK_METHOD1(attachEventBase, void(folly::EventBase*));
  MOCK_METHOD0(detachEventBase, void());
  MOCK_METHOD1(setControlStream, folly::Optional<LocalErrorCode>(StreamId));

  MOCK_METHOD2(
      setPeekCallback,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId, PeekCallback*));

  MOCK_METHOD1(
      pausePeek,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId));
  MOCK_METHOD1(
      resumePeek,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId));

  MOCK_METHOD2(
      peek,
      folly::Expected<folly::Unit, LocalErrorCode>(
          StreamId,
          const folly::Function<
              void(StreamId, const folly::Range<PeekIterator>&) const>&));

  MOCK_METHOD3(
      consume,
      folly::Expected<
          folly::Unit,
          std::pair<LocalErrorCode, folly::Optional<uint64_t>>>(
          StreamId,
          uint64_t,
          size_t));
  MOCK_METHOD2(
      consume,
      folly::Expected<folly::Unit, LocalErrorCode>(StreamId, size_t));

  MOCK_METHOD1(setCongestionControl, void(CongestionControlType));

  ConnectionSetupCallback* setupCb_;
  ConnectionCallbackNew* connCb_;

  folly::Function<bool(const folly::Optional<std::string>&, const Buf&)>
      earlyDataAppParamsValidator_;
  folly::Function<Buf()> earlyDataAppParamsGetter_;

  MOCK_METHOD1(addObserver, void(Observer*));
  MOCK_METHOD1(removeObserver, bool(Observer*));
  MOCK_CONST_METHOD0(getObservers, const ObserverVec&());
  MOCK_METHOD2(
      resetNonControlStreams,
      void(ApplicationErrorCode, folly::StringPiece));
  MOCK_CONST_METHOD0(getConnectionsStats, QuicConnectionStats());
  MOCK_METHOD1(
      setDatagramCallback,
      folly::Expected<folly::Unit, LocalErrorCode>(DatagramCallback*));
  MOCK_CONST_METHOD0(getDatagramSizeLimit, uint16_t());
  folly::Expected<folly::Unit, LocalErrorCode> writeDatagram(
      Buf data) override {
    SharedBuf sharedData(data.release());
    return writeDatagram(sharedData);
  }
  MOCK_METHOD1(writeDatagram, WriteResult(SharedBuf));
  MOCK_METHOD1(
      readDatagrams,
      folly::Expected<std::vector<Buf>, LocalErrorCode>(size_t));
};
} // namespace quic
