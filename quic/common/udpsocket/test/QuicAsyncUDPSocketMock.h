/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>

namespace quic::test {

class QuicAsyncUDPSocketMock : public QuicAsyncUDPSocket {
 public:
  MOCK_METHOD((void), init, (sa_family_t));
  MOCK_METHOD((void), bind, (const folly::SocketAddress&));
  MOCK_METHOD((bool), isBound, (), (const));
  MOCK_METHOD((void), connect, (const folly::SocketAddress&));
  MOCK_METHOD((void), close, ());
  MOCK_METHOD((void), resumeRead, (ReadCallback*));
  MOCK_METHOD((void), pauseRead, ());
  MOCK_METHOD(
      (ssize_t),
      write,
      (const folly::SocketAddress&, const std::unique_ptr<folly::IOBuf>&));
  MOCK_METHOD(
      (int),
      writem,
      (folly::Range<folly::SocketAddress const*>,
       const std::unique_ptr<folly::IOBuf>*,
       size_t));
  MOCK_METHOD(
      ssize_t,
      writeGSO,
      (const folly::SocketAddress&,
       const std::unique_ptr<folly::IOBuf>&,
       WriteOptions));
  MOCK_METHOD(
      (int),
      writemGSO,
      (folly::Range<folly::SocketAddress const*>,
       const std::unique_ptr<folly::IOBuf>*,
       size_t,
       const WriteOptions*));
  MOCK_METHOD((ssize_t), recvmsg, (struct msghdr*, int));
  MOCK_METHOD(
      (int),
      recvmmsg,
      (struct mmsghdr*, unsigned int, unsigned int, struct timespec*));
  MOCK_METHOD(
      (RecvResult),
      recvmmsgNetworkData,
      (uint64_t,
       uint16_t,
       NetworkData&,
       folly::Optional<folly::SocketAddress>&,
       size_t&));
  MOCK_METHOD((int), getGSO, ());
  MOCK_METHOD((int), getGRO, ());
  MOCK_METHOD((bool), setGRO, (bool));
  MOCK_METHOD((const folly::SocketAddress&), setGSO, (), (const));
  MOCK_METHOD((void), attachEventBase, (std::shared_ptr<QuicEventBase>));
  MOCK_METHOD((void), detachEventBase, ());
  MOCK_METHOD((std::shared_ptr<QuicEventBase>), getEventBase, (), (const));
  MOCK_METHOD((void), setCmsgs, (const folly::SocketCmsgMap&));
  MOCK_METHOD((void), appendCmsgs, (const folly::SocketCmsgMap&));
  MOCK_METHOD(
      (void),
      setAdditionalCmsgsFunc,
      (folly::Function<folly::Optional<folly::SocketCmsgMap>()> &&));
  MOCK_METHOD((int), getTimestamping, ());
  MOCK_METHOD((void), setReuseAddr, (bool));
  MOCK_METHOD((void), setDFAndTurnOffPMTU, (bool));
  MOCK_METHOD((void), setErrMessageCallback, (ErrMessageCallback*));
  MOCK_METHOD(
      (void),
      applyOptions,
      (const folly::SocketOptionMap&, folly::SocketOptionKey::ApplyPos));
  MOCK_METHOD((void), setReusePort, (bool));
  MOCK_METHOD((void), setRcvBuf, (int));
  MOCK_METHOD((void), setSndBuf, (int));
  MOCK_METHOD((void), setFD, (int, FDOwnership));
  MOCK_METHOD((int), getFD, ());
  MOCK_METHOD((const folly::SocketAddress&), address, (), (const));
  MOCK_METHOD((void), setDFAndTurnOffPMTU, ());
};

} // namespace quic::test
