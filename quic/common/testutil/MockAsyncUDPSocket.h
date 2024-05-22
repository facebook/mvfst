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

  MOCK_METHOD(void, init, (sa_family_t));
  MOCK_METHOD(const folly::SocketAddress&, address, (), (const));
  MOCK_METHOD(void, bind, (const folly::SocketAddress&));
  MOCK_METHOD(void, setFD, (int, QuicAsyncUDPSocket::FDOwnership));
  MOCK_METHOD(
      ssize_t,
      write,
      (const folly::SocketAddress&, const std::unique_ptr<folly::IOBuf>&));
  MOCK_METHOD(
      int,
      writem,
      (folly::Range<folly::SocketAddress const*>,
       const std::unique_ptr<folly::IOBuf>*,
       size_t));
  MOCK_METHOD(
      ssize_t,
      writeGSO,
      (const folly::SocketAddress&,
       const std::unique_ptr<folly::IOBuf>&,
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
      RecvResult,
      recvmmsgNetworkData,
      (uint64_t readBufferSize,
       uint16_t numPackets,
       NetworkData& networkData,
       folly::Optional<folly::SocketAddress>& peerAddress,
       size_t& totalData));
  MOCK_METHOD(int, getGRO, ());
  MOCK_METHOD(bool, setGRO, (bool));
  MOCK_METHOD(
      void,
      setAdditionalCmsgsFunc,
      (folly::Function<folly::Optional<folly::SocketCmsgMap>()>&&));
  MOCK_METHOD(void, setRcvBuf, (int));
  MOCK_METHOD(void, setSndBuf, (int));
  MOCK_METHOD(int, getTimestamping, ());
  MOCK_METHOD(void, resumeRead, (QuicAsyncUDPSocket::ReadCallback*));
  MOCK_METHOD(void, pauseRead, ());
  MOCK_METHOD(void, close, ());
  MOCK_METHOD(void, setDFAndTurnOffPMTU, ());
  MOCK_METHOD(int, getFD, ());
  MOCK_METHOD(void, setReusePort, (bool));
  MOCK_METHOD(void, setReuseAddr, (bool));
  MOCK_METHOD(void, dontFragment, (bool));
  MOCK_METHOD(
      void,
      setErrMessageCallback,
      (QuicAsyncUDPSocket::ErrMessageCallback*));
  MOCK_METHOD(void, connect, (const folly::SocketAddress&));
  MOCK_METHOD(bool, isBound, (), (const));
  MOCK_METHOD(int, getGSO, ());
  MOCK_METHOD(bool, setGSO, (int));
  MOCK_METHOD(ssize_t, recvmsg, (struct msghdr*, int));
  MOCK_METHOD(
      int,
      recvmmsg,
      (struct mmsghdr*, unsigned int, unsigned int, struct timespec*));
  MOCK_METHOD(void, setCmsgs, (const folly::SocketCmsgMap&));
  MOCK_METHOD(
      void,
      setNontrivialCmsgs,
      (const folly::SocketNontrivialCmsgMap&));
  MOCK_METHOD(void, appendCmsgs, (const folly::SocketCmsgMap&));
  MOCK_METHOD(
      void,
      appendNontrivialCmsgs,
      (const folly::SocketNontrivialCmsgMap&));
  MOCK_METHOD(
      void,
      applyOptions,
      (const folly::SocketOptionMap&, folly::SocketOptionKey::ApplyPos));
  MOCK_METHOD((void), setRecvTos, (bool));
  MOCK_METHOD((bool), getRecvTos, ());
  MOCK_METHOD((void), setTosOrTrafficClass, (uint8_t));
  MOCK_METHOD((bool), isWritableCallbackSet, (), (const));
  MOCK_METHOD(
      (folly::Expected<folly::Unit, folly::AsyncSocketException>),
      resumeWrite,
      (WriteCallback*));
  MOCK_METHOD((void), pauseWrite, ());
};

} // namespace quic::test
