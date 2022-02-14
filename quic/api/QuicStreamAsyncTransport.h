/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/AsyncTransport.h>
#include <quic/api/QuicSocket.h>

namespace quic {

/**
 * Adaptor for multiplexing over quic an existing use-case that
 * expects an AsyncTransport
 */
class QuicStreamAsyncTransport : public folly::AsyncTransport,
                                 public QuicSocket::ReadCallback,
                                 public QuicSocket::WriteCallback,
                                 public folly::EventBase::LoopCallback {
 public:
  using UniquePtr = std::unique_ptr<
      QuicStreamAsyncTransport,
      folly::DelayedDestruction::Destructor>;

  static UniquePtr createWithNewStream(std::shared_ptr<quic::QuicSocket> sock);

  static UniquePtr createWithExistingStream(
      std::shared_ptr<quic::QuicSocket> sock,
      quic::StreamId streamId);

 protected:
  QuicStreamAsyncTransport() = default;
  ~QuicStreamAsyncTransport() override = default;

  void setSocket(std::shared_ptr<QuicSocket> sock);

  // While stream id is not set, all writes are buffered.
  void setStreamId(StreamId id);

 public:
  //
  // folly::DelayedDestruction
  //
  void destroy() override;

  //
  // folly::AsyncTransport overrides
  //
  void setReadCB(AsyncTransport::ReadCallback* callback) override;

  AsyncTransport::ReadCallback* getReadCallback() const override;

  void write(
      AsyncTransport::WriteCallback* callback,
      const void* buf,
      size_t bytes,
      folly::WriteFlags flags = folly::WriteFlags::NONE) override;

  void writev(
      AsyncTransport::WriteCallback* callback,
      const iovec* vec,
      size_t count,
      folly::WriteFlags flags = folly::WriteFlags::NONE) override;
  void writeChain(
      AsyncTransport::WriteCallback* callback,
      std::unique_ptr<folly::IOBuf>&& buf,
      folly::WriteFlags flags = folly::WriteFlags::NONE) override;

  void close() override;
  void closeNow() override;

  void closeWithReset() override;

  void shutdownWrite() override;

  void shutdownWriteNow() override;

  bool good() const override;

  bool readable() const override;

  bool writable() const override;

  bool isPending() const override;

  bool connecting() const override;

  bool error() const override;

  folly::EventBase* getEventBase() const override;

  void attachEventBase(folly::EventBase* /*eventBase*/) override;

  void detachEventBase() override;

  bool isDetachable() const override;

  void setSendTimeout(uint32_t /*milliseconds*/) override;

  uint32_t getSendTimeout() const override;

  void getLocalAddress(folly::SocketAddress* address) const override;

  void getPeerAddress(folly::SocketAddress* address) const override;

  bool isEorTrackingEnabled() const override;

  void setEorTracking(bool track) override;

  size_t getAppBytesWritten() const override;

  size_t getRawBytesWritten() const override;

  size_t getAppBytesReceived() const override;

  size_t getRawBytesReceived() const override;

  std::string getApplicationProtocol() const noexcept override;

  std::string getSecurityProtocol() const override;

 protected:
  //
  // QucSocket::ReadCallback overrides
  //
  void readAvailable(quic::StreamId /*streamId*/) noexcept override;
  void readError(quic::StreamId /*streamId*/, QuicError error) noexcept
      override;

  //
  // QucSocket::WriteCallback overrides
  //
  void onStreamWriteReady(quic::StreamId /*id*/, uint64_t maxToSend) noexcept
      override;
  void onStreamWriteError(StreamId /*id*/, QuicError error) noexcept override;

  //
  // folly::EventBase::LoopCallback overrides
  //
  void runLoopCallback() noexcept override;

  // Utils
  void addWriteCallback(AsyncTransport::WriteCallback* callback, size_t offset);
  void handleWriteOffsetError(
      AsyncTransport::WriteCallback* callback,
      LocalErrorCode error);
  bool handleWriteStateError(AsyncTransport::WriteCallback* callback);
  void handleRead();
  void send(uint64_t maxToSend);
  folly::Expected<size_t, LocalErrorCode> getStreamWriteOffset() const;
  void invokeWriteCallbacks(size_t sentOffset);
  void failWrites(const folly::AsyncSocketException& ex);
  void closeNowImpl(folly::AsyncSocketException&& ex);

  enum class CloseState { OPEN, CLOSING, CLOSED };
  CloseState state_{CloseState::OPEN};
  std::shared_ptr<quic::QuicSocket> sock_;
  folly::Optional<quic::StreamId> id_;
  enum class EOFState { NOT_SEEN, QUEUED, DELIVERED };
  EOFState readEOF_{EOFState::NOT_SEEN};
  EOFState writeEOF_{EOFState::NOT_SEEN};
  AsyncTransport::ReadCallback* readCb_{nullptr};
  folly::IOBufQueue writeBuf_{folly::IOBufQueue::cacheChainLength()};
  std::deque<std::pair<size_t, AsyncTransport::WriteCallback*>> writeCallbacks_;
  folly::Optional<folly::AsyncSocketException> ex_;
};
} // namespace quic
