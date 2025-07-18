/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>

#include <folly/portability/GMock.h>

namespace quic::test {

struct MockAsyncUDPSocket : public FollyQuicAsyncUDPSocket {
  explicit MockAsyncUDPSocket(std::shared_ptr<FollyQuicEventBase> evb)
      : FollyQuicAsyncUDPSocket(std::move(evb)) {}

  ~MockAsyncUDPSocket() override {}

  MOCK_METHOD((quic::Expected<void, QuicError>), init, (sa_family_t));
  MOCK_METHOD(
      (quic::Expected<folly::SocketAddress, QuicError>),
      address,
      (),
      (const));
  MOCK_METHOD((const folly::SocketAddress&), addressRef, (), (const));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      bind,
      (const folly::SocketAddress&));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      setFD,
      (int, QuicAsyncUDPSocket::FDOwnership));
  MOCK_METHOD(
      ssize_t,
      write,
      (const folly::SocketAddress&, const struct iovec*, size_t));
  MOCK_METHOD(
      int,
      writem,
      (folly::Range<folly::SocketAddress const*>, iovec*, size_t*, size_t));
  MOCK_METHOD(
      ssize_t,
      writeGSO,
      (const folly::SocketAddress&,
       const struct iovec*,
       size_t,
       QuicAsyncUDPSocket::WriteOptions));
  MOCK_METHOD(
      ssize_t,
      writev,
      (const folly::SocketAddress&, const struct iovec*, size_t));
  MOCK_METHOD(
      int,
      writemGSO,
      (folly::Range<folly::SocketAddress const*> addrs,
       const std::unique_ptr<folly::IOBuf>* bufs,
       size_t count,
       const WriteOptions* options));
  MOCK_METHOD(
      int,
      writemGSO,
      (folly::Range<folly::SocketAddress const*> addrs,
       iovec* iov,
       size_t* numIovecsInBuffer,
       size_t count,
       const WriteOptions* options));
  MOCK_METHOD(
      (quic::Expected<RecvResult, QuicError>),
      recvmmsgNetworkData,
      (uint64_t readBufferSize,
       uint16_t numPackets,
       NetworkData& networkData,
       Optional<folly::SocketAddress>& peerAddress,
       size_t& totalData));
  MOCK_METHOD((quic::Expected<int, QuicError>), getGRO, ());
  MOCK_METHOD((quic::Expected<void, QuicError>), setGRO, (bool));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      setAdditionalCmsgsFunc,
      (std::function<Optional<folly::SocketCmsgMap>()>&&));
  MOCK_METHOD((quic::Expected<void, QuicError>), setRcvBuf, (int));
  MOCK_METHOD((quic::Expected<void, QuicError>), setSndBuf, (int));
  MOCK_METHOD((quic::Expected<int, QuicError>), getTimestamping, ());
  MOCK_METHOD(void, resumeRead, (QuicAsyncUDPSocket::ReadCallback*));
  MOCK_METHOD(void, pauseRead, ());
  MOCK_METHOD((quic::Expected<void, QuicError>), close, ());
  MOCK_METHOD((quic::Expected<void, QuicError>), setDFAndTurnOffPMTU, ());
  MOCK_METHOD(int, getFD, ());
  MOCK_METHOD((quic::Expected<void, QuicError>), setReusePort, (bool));
  MOCK_METHOD((quic::Expected<void, QuicError>), setReuseAddr, (bool));
  MOCK_METHOD(void, dontFragment, (bool));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      setErrMessageCallback,
      (QuicAsyncUDPSocket::ErrMessageCallback*));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      connect,
      (const folly::SocketAddress&));
  MOCK_METHOD(bool, isBound, (), (const));
  MOCK_METHOD((quic::Expected<int, QuicError>), getGSO, ());
  MOCK_METHOD((quic::Expected<void, QuicError>), setGSO, (int));
  MOCK_METHOD(ssize_t, recvmsg, (struct msghdr*, int));
  MOCK_METHOD(
      int,
      recvmmsg,
      (struct mmsghdr*, unsigned int, unsigned int, struct timespec*));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      setCmsgs,
      (const folly::SocketCmsgMap&));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      setNontrivialCmsgs,
      (const folly::SocketNontrivialCmsgMap&));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      appendCmsgs,
      (const folly::SocketCmsgMap&));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      appendNontrivialCmsgs,
      (const folly::SocketNontrivialCmsgMap&));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      applyOptions,
      (const folly::SocketOptionMap&, folly::SocketOptionKey::ApplyPos));
  MOCK_METHOD((quic::Expected<void, QuicError>), setRecvTos, (bool));
  MOCK_METHOD((quic::Expected<bool, QuicError>), getRecvTos, ());
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      setTosOrTrafficClass,
      (uint8_t));
  MOCK_METHOD((bool), isWritableCallbackSet, (), (const));
  MOCK_METHOD((quic::Expected<void, QuicError>), resumeWrite, (WriteCallback*));
  MOCK_METHOD((void), pauseWrite, ());
};

} // namespace quic::test
