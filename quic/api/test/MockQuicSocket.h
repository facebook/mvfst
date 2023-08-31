/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>

#include <quic/api/QuicSocket.h>
#include <quic/dsr/Types.h>

namespace quic {

class MockQuicSocket : public QuicSocket {
 public:
  using SharedBuf = std::shared_ptr<folly::IOBuf>;

  MockQuicSocket() = default;

  MockQuicSocket(
      folly::EventBase* /*eventBase*/,
      ConnectionSetupCallback* setupCb,
      ConnectionCallback* connCb)
      : setupCb_(setupCb), connCb_(connCb) {}

  MOCK_METHOD(bool, good, (), (const));
  MOCK_METHOD(bool, replaySafe, (), (const));
  MOCK_METHOD(bool, error, (), (const));
  MOCK_METHOD(void, close, (folly::Optional<QuicError>));
  MOCK_METHOD(void, closeGracefully, ());
  MOCK_METHOD(void, closeNow, (folly::Optional<QuicError>));
  MOCK_METHOD(
      folly::Optional<quic::ConnectionId>,
      getClientConnectionId,
      (),
      (const));
  MOCK_METHOD(const TransportSettings&, getTransportSettings, (), (const));
  MOCK_METHOD(
      folly::Optional<quic::ConnectionId>,
      getServerConnectionId,
      (),
      (const));
  MOCK_METHOD(
      folly::Optional<quic::ConnectionId>,
      getClientChosenDestConnectionId,
      (),
      (const));
  MOCK_METHOD(const folly::SocketAddress&, getPeerAddress, (), (const));
  MOCK_METHOD(const folly::SocketAddress&, getOriginalPeerAddress, (), (const));
  MOCK_METHOD(const folly::SocketAddress&, getLocalAddress, (), (const));
  MOCK_METHOD(folly::EventBase*, getEventBase, (), (const));
  MOCK_METHOD(
      (folly::Expected<size_t, LocalErrorCode>),
      getStreamReadOffset,
      (StreamId),
      (const));
  MOCK_METHOD(
      (folly::Expected<size_t, LocalErrorCode>),
      getStreamWriteOffset,
      (StreamId),
      (const));
  MOCK_METHOD(
      (folly::Expected<size_t, LocalErrorCode>),
      getStreamWriteBufferedBytes,
      (StreamId),
      (const));
  MOCK_METHOD(QuicSocket::TransportInfo, getTransportInfo, (), (const));
  MOCK_METHOD(
      (folly::Expected<QuicSocket::StreamTransportInfo, LocalErrorCode>),
      getStreamTransportInfo,
      (StreamId),
      (const));
  MOCK_METHOD(folly::Optional<std::string>, getAppProtocol, (), (const));
  MOCK_METHOD(void, setReceiveWindow, (StreamId, size_t));
  MOCK_METHOD(void, setSendBuffer, (StreamId, size_t, size_t));
  MOCK_METHOD(uint64_t, getConnectionBufferAvailable, (), (const));
  MOCK_METHOD(
      (folly::Expected<FlowControlState, LocalErrorCode>),
      getConnectionFlowControl,
      (),
      (const));
  MOCK_METHOD(
      (folly::Expected<FlowControlState, LocalErrorCode>),
      getStreamFlowControl,
      (StreamId),
      (const));
  MOCK_METHOD(
      (folly::Expected<uint64_t, LocalErrorCode>),
      getMaxWritableOnStream,
      (StreamId),
      (const));
  MOCK_METHOD(void, unsetAllReadCallbacks, ());
  MOCK_METHOD(void, unsetAllPeekCallbacks, ());
  MOCK_METHOD(void, unsetAllDeliveryCallbacks, ());
  MOCK_METHOD(void, cancelDeliveryCallbacksForStream, (StreamId));
  MOCK_METHOD(
      void,
      cancelDeliveryCallbacksForStream,
      (StreamId, uint64_t offset));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setConnectionFlowControlWindow,
      (uint64_t));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setStreamFlowControlWindow,
      (StreamId, uint64_t));
  MOCK_METHOD(void, setTransportSettings, (TransportSettings));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setMaxPacingRate,
      (uint64_t));
  folly::Expected<folly::Unit, LocalErrorCode>
  setKnob(uint64_t knobSpace, uint64_t knobId, Buf knobBlob) override {
    SharedBuf sharedBlob(knobBlob.release());
    return setKnob(knobSpace, knobId, sharedBlob);
  }
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setKnob,
      (uint64_t, uint64_t, SharedBuf));
  MOCK_METHOD(bool, isKnobSupported, (), (const));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setStreamPriority,
      (StreamId, Priority));
  MOCK_METHOD(
      (folly::Expected<Priority, LocalErrorCode>),
      getStreamPriority,
      (StreamId));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setReadCallback,
      (StreamId, ReadCallback*, folly::Optional<ApplicationErrorCode> err));
  MOCK_METHOD(void, setConnectionSetupCallback, (ConnectionSetupCallback*));
  MOCK_METHOD(void, setConnectionCallback, (ConnectionCallback*));
  void setEarlyDataAppParamsFunctions(
      folly::Function<bool(const folly::Optional<std::string>&, const Buf&)
                          const> validator,
      folly::Function<Buf()> getter) override {
    earlyDataAppParamsValidator_ = std::move(validator);
    earlyDataAppParamsGetter_ = std::move(getter);
  }
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      pauseRead,
      (StreamId));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      resumeRead,
      (StreamId));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      stopSending,
      (StreamId, ApplicationErrorCode));
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
  MOCK_METHOD(ReadResult, readNaked, (StreamId, size_t));
  MOCK_METHOD(
      (folly::Expected<StreamId, LocalErrorCode>),
      createBidirectionalStream,
      (bool));
  MOCK_METHOD(
      (folly::Expected<StreamId, LocalErrorCode>),
      createUnidirectionalStream,
      (bool));
  MOCK_METHOD(uint64_t, getNumOpenableBidirectionalStreams, (), (const));
  MOCK_METHOD(uint64_t, getNumOpenableUnidirectionalStreams, (), (const));
  MOCK_METHOD((bool), isClientStream, (StreamId), (noexcept));
  MOCK_METHOD((bool), isServerStream, (StreamId), (noexcept));
  MOCK_METHOD((StreamInitiator), getStreamInitiator, (StreamId), (noexcept));
  MOCK_METHOD((bool), isBidirectionalStream, (StreamId), (noexcept));
  MOCK_METHOD((bool), isUnidirectionalStream, (StreamId), (noexcept));
  MOCK_METHOD(
      (StreamDirectionality),
      getStreamDirectionality,
      (StreamId),
      (noexcept));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      notifyPendingWriteOnConnection,
      (WriteCallback*));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      notifyPendingWriteOnStream,
      (StreamId, WriteCallback*));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      unregisterStreamWriteCallback,
      (StreamId));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      registerTxCallback,
      (const StreamId, const uint64_t, ByteEventCallback*));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      registerByteEventCallback,
      (const ByteEvent::Type,
       const StreamId,
       const uint64_t,
       ByteEventCallback*));
  MOCK_METHOD(
      void,
      cancelByteEventCallbacksForStream,
      (const StreamId id, const folly::Optional<uint64_t>& offset));
  MOCK_METHOD(
      void,
      cancelByteEventCallbacksForStream,
      (const ByteEvent::Type,
       const StreamId id,
       const folly::Optional<uint64_t>& offset));
  MOCK_METHOD(void, cancelAllByteEventCallbacks, ());
  MOCK_METHOD(void, cancelByteEventCallbacks, (const ByteEvent::Type));
  MOCK_METHOD(
      size_t,
      getNumByteEventCallbacksForStream,
      (const StreamId id),
      (const));
  MOCK_METHOD(
      size_t,
      getNumByteEventCallbacksForStream,
      (const ByteEvent::Type, const StreamId),
      (const));
  folly::Expected<folly::Unit, LocalErrorCode>
  writeChain(StreamId id, Buf data, bool eof, ByteEventCallback* cb) override {
    SharedBuf sharedData(data.release());
    return writeChain(id, sharedData, eof, cb);
  }
  MOCK_METHOD(
      WriteResult,
      writeChain,
      (StreamId, SharedBuf, bool, ByteEventCallback*));
  MOCK_METHOD(
      WriteResult,
      writeBufMeta,
      (StreamId, const BufferMeta&, bool, ByteEventCallback*));
  MOCK_METHOD(
      WriteResult,
      setDSRPacketizationRequestSender,
      (StreamId, std::unique_ptr<DSRPacketizationRequestSender>));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      registerDeliveryCallback,
      (StreamId, uint64_t, ByteEventCallback*));
  MOCK_METHOD(folly::Optional<LocalErrorCode>, shutdownWrite, (StreamId));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      resetStream,
      (StreamId, ApplicationErrorCode));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      maybeResetStreamFromReadError,
      (StreamId, QuicErrorCode));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setPingCallback,
      (PingCallback*));
  MOCK_METHOD(void, sendPing, (std::chrono::milliseconds));
  MOCK_METHOD(const QuicConnectionStateBase*, getState, (), (const));
  MOCK_METHOD(bool, isDetachable, ());
  MOCK_METHOD(void, attachEventBase, (folly::EventBase*));
  MOCK_METHOD(void, detachEventBase, ());
  MOCK_METHOD(folly::Optional<LocalErrorCode>, setControlStream, (StreamId));

  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setPeekCallback,
      (StreamId, PeekCallback*));

  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      pausePeek,
      (StreamId));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      resumePeek,
      (StreamId));

  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      peek,
      (StreamId,
       const folly::Function<void(StreamId, const folly::Range<PeekIterator>&)
                                 const>&));

  MOCK_METHOD(
      (folly::Expected<
          folly::Unit,
          std::pair<LocalErrorCode, folly::Optional<uint64_t>>>),
      consume,
      (StreamId, uint64_t, size_t));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      consume,
      (StreamId, size_t));

  MOCK_METHOD(void, setCongestionControl, (CongestionControlType));

  MOCK_METHOD(void, addPacketProcessor, (std::shared_ptr<PacketProcessor>));

  MOCK_METHOD(
      void,
      setThrottlingSignalProvider,
      (std::shared_ptr<ThrottlingSignalProvider>));

  ConnectionSetupCallback* setupCb_{nullptr};
  ConnectionCallback* connCb_{nullptr};

  folly::Function<bool(const folly::Optional<std::string>&, const Buf&)>
      earlyDataAppParamsValidator_;
  folly::Function<Buf()> earlyDataAppParamsGetter_;

  MOCK_METHOD(
      void,
      resetNonControlStreams,
      (ApplicationErrorCode, folly::StringPiece));
  MOCK_METHOD(QuicConnectionStats, getConnectionsStats, (), (const));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setDatagramCallback,
      (DatagramCallback*));
  MOCK_METHOD(uint16_t, getDatagramSizeLimit, (), (const));
  folly::Expected<folly::Unit, LocalErrorCode> writeDatagram(
      Buf data) override {
    SharedBuf sharedData(data.release());
    return writeDatagram(sharedData);
  }
  MOCK_METHOD(WriteResult, writeDatagram, (SharedBuf));
  MOCK_METHOD(
      (folly::Expected<std::vector<ReadDatagram>, LocalErrorCode>),
      readDatagrams,
      (size_t));
  MOCK_METHOD(
      (folly::Expected<std::vector<Buf>, LocalErrorCode>),
      readDatagramBufs,
      (size_t));
  MOCK_METHOD(
      SocketObserverContainer*,
      getSocketObserverContainer,
      (),
      (const));
  MOCK_METHOD(
      (folly::Expected<StreamGroupId, LocalErrorCode>),
      createBidirectionalStreamGroup,
      ());
  MOCK_METHOD(
      (folly::Expected<StreamGroupId, LocalErrorCode>),
      createUnidirectionalStreamGroup,
      ());
  MOCK_METHOD(
      (folly::Expected<StreamId, LocalErrorCode>),
      createBidirectionalStreamInGroup,
      (StreamGroupId));
  MOCK_METHOD(
      (folly::Expected<StreamId, LocalErrorCode>),
      createUnidirectionalStreamInGroup,
      (StreamGroupId));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setStreamGroupRetransmissionPolicy,
      (StreamGroupId, std::optional<QuicStreamGroupRetransmissionPolicy>),
      (noexcept));
  MOCK_METHOD(
      (const std::shared_ptr<const folly::AsyncTransportCertificate>),
      getPeerCertificate,
      (),
      (const));
};
} // namespace quic
