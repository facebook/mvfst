/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/client/QuicClientTransport.h>

namespace quic::test {

class QuicClientTransportMock : public QuicClientTransport {
 public:
  QuicClientTransportMock(
      std::shared_ptr<QuicEventBase> evb,
      std::unique_ptr<QuicAsyncUDPSocket> socket,
      std::shared_ptr<ClientHandshakeFactory> handshakeFactory)
      : QuicClientTransport(
            std::move(evb),
            std::move(socket),
            std::move(handshakeFactory)) {}

  MOCK_METHOD(
      (folly::Expected<std::pair<Buf, bool>, LocalErrorCode>),
      read,
      (StreamId, size_t));
  MOCK_METHOD(
      (void),
      onReadError,
      (const folly::AsyncSocketException&),
      (noexcept));
  MOCK_METHOD((void), getReadBuffer, (void**, size_t*), (noexcept));
  MOCK_METHOD(
      (void),
      onDataAvailable,
      (const folly::SocketAddress&, size_t, bool, OnDataAvailableParams),
      (noexcept));
  MOCK_METHOD((bool), shouldOnlyNotify, ());
  MOCK_METHOD((void), onNotifyDataAvailable, (QuicAsyncUDPSocket&), (noexcept));
  MOCK_METHOD((void), errMessage, (const cmsghdr&), (noexcept));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, LocalErrorCode>),
      setReadCallback,
      (StreamId,
       quic::QuicSocket::ReadCallback*,
       Optional<ApplicationErrorCode>));
  MOCK_METHOD(
      (folly::Expected<StreamTransportInfo, LocalErrorCode>),
      getStreamTransportInfo,
      (StreamId),
      (const));
  MOCK_METHOD((bool), isTLSResumed, (), (const));
  MOCK_METHOD((ZeroRttAttemptState), getZeroRttState, ());
  MOCK_METHOD((void), closeImpl, (Optional<QuicError>, bool, bool));
  MOCK_METHOD((void), close, (Optional<QuicError>));
  MOCK_METHOD((void), writeData, ());
  MOCK_METHOD((void), closeSecondSocket, ());
  MOCK_METHOD((void), setHappyEyeballsEnabled, (bool));
  MOCK_METHOD(
      (WriteResult),
      writeChain,
      (StreamId, Buf, bool, ByteEventCallback*));
  MOCK_METHOD((uint64_t), maxWritableOnConn, (), (const));
};

} // namespace quic::test
