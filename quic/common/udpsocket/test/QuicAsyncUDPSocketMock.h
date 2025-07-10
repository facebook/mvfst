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
  MOCK_METHOD((quic::Expected<void, QuicError>), init, (sa_family_t));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      bind,
      (const folly::SocketAddress&));
  MOCK_METHOD((bool), isBound, (), (const));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      connect,
      (const folly::SocketAddress&));
  MOCK_METHOD((quic::Expected<void, QuicError>), close, ());
  MOCK_METHOD((void), resumeRead, (ReadCallback*));
  MOCK_METHOD((void), pauseRead, ());
  MOCK_METHOD(
      (ssize_t),
      write,
      (const folly::SocketAddress&, const struct iovec* vec, size_t iovec_len));
  MOCK_METHOD(
      (int),
      writem,
      (folly::Range<folly::SocketAddress const*>, iovec*, size_t*, size_t));
  MOCK_METHOD(
      ssize_t,
      writeGSO,
      (const folly::SocketAddress&,
       const struct iovec* vec,
       size_t iovec_len,
       WriteOptions));
  MOCK_METHOD(
      (int),
      writemGSO,
      (folly::Range<folly::SocketAddress const*>,
       const std::unique_ptr<folly::IOBuf>*,
       size_t,
       const WriteOptions*));
  MOCK_METHOD(
      (int),
      writemGSO,
      (folly::Range<folly::SocketAddress const*>,
       iovec*,
       size_t*,
       size_t,
       const WriteOptions*));
  MOCK_METHOD((ssize_t), recvmsg, (struct msghdr*, int));
  MOCK_METHOD(
      (int),
      recvmmsg,
      (struct mmsghdr*, unsigned int, unsigned int, struct timespec*));
  MOCK_METHOD(
      (quic::Expected<RecvResult, QuicError>),
      recvmmsgNetworkData,
      (uint64_t,
       uint16_t,
       NetworkData&,
       Optional<folly::SocketAddress>&,
       size_t&));
  MOCK_METHOD((quic::Expected<int, QuicError>), getGSO, ());
  MOCK_METHOD((quic::Expected<int, QuicError>), getGRO, ());
  MOCK_METHOD((quic::Expected<void, QuicError>), setGRO, (bool));
  MOCK_METHOD(
      (quic::Expected<folly::SocketAddress, QuicError>),
      address,
      (),
      (const));
  MOCK_METHOD((const folly::SocketAddress&), addressRef, (), (const));
  MOCK_METHOD((void), attachEventBase, (std::shared_ptr<QuicEventBase>));
  MOCK_METHOD((void), detachEventBase, ());
  MOCK_METHOD((std::shared_ptr<QuicEventBase>), getEventBase, (), (const));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      setCmsgs,
      (const folly::SocketCmsgMap&));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      appendCmsgs,
      (const folly::SocketCmsgMap&));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      setAdditionalCmsgsFunc,
      (std::function<Optional<folly::SocketCmsgMap>()>&&));
  MOCK_METHOD((quic::Expected<int, QuicError>), getTimestamping, ());
  MOCK_METHOD((quic::Expected<void, QuicError>), setReuseAddr, (bool));
  MOCK_METHOD((quic::Expected<void, QuicError>), setDFAndTurnOffPMTU, ());
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      setErrMessageCallback,
      (ErrMessageCallback*));
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      applyOptions,
      (const folly::SocketOptionMap&, folly::SocketOptionKey::ApplyPos));
  MOCK_METHOD((quic::Expected<void, QuicError>), setReusePort, (bool));
  MOCK_METHOD((quic::Expected<void, QuicError>), setRcvBuf, (int));
  MOCK_METHOD((quic::Expected<void, QuicError>), setSndBuf, (int));
  MOCK_METHOD((quic::Expected<void, QuicError>), setFD, (int, FDOwnership));
  MOCK_METHOD((int), getFD, ());
  MOCK_METHOD((quic::Expected<void, QuicError>), setRecvTos, (bool));
  MOCK_METHOD((quic::Expected<bool, QuicError>), getRecvTos, ());
  MOCK_METHOD(
      (quic::Expected<void, QuicError>),
      setTosOrTrafficClass,
      (uint8_t));
  MOCK_METHOD(
      (quic::Expected<sa_family_t, QuicError>),
      getLocalAddressFamily,
      (),
      (const));
};

class MockErrMessageCallback
    : public quic::QuicAsyncUDPSocket::ErrMessageCallback {
 public:
  ~MockErrMessageCallback() override = default;

  MOCK_METHOD(void, errMessage_, (const cmsghdr&));

  void errMessage(const cmsghdr& cmsg) noexcept override {
    try {
      errMessage_(cmsg);
    } catch (std::exception) {
      // Swallow exception from mock function to keep linter happy.
    }
  }

  MOCK_METHOD(void, errMessageError_, (const folly::AsyncSocketException&));

  void errMessageError(
      const folly::AsyncSocketException& ex) noexcept override {
    try {
      errMessageError_(ex);
    } catch (std::exception) {
      // Swallow exception from mock function to keep linter happy.
    }
  }
};

class MockUDPReadCallback : public quic::QuicAsyncUDPSocket::ReadCallback {
 public:
  ~MockUDPReadCallback() override = default;

  MOCK_METHOD(void, getReadBuffer_, (void**, size_t*));

  void getReadBuffer(void** buf, size_t* len) noexcept override {
    try {
      getReadBuffer_(buf, len);
    } catch (std::exception) {
      // Swallow exception from mock function to keep linter happy.
    }
  }

  MOCK_METHOD(bool, shouldOnlyNotify, ());
  MOCK_METHOD(void, onNotifyDataAvailable_, (quic::QuicAsyncUDPSocket&));

  void onNotifyDataAvailable(quic::QuicAsyncUDPSocket& sock) noexcept override {
    try {
      onNotifyDataAvailable_(sock);
    } catch (std::exception) {
      // Swallow exception from mock function to keep linter happy.
    }
  }

  MOCK_METHOD(
      void,
      onDataAvailable_,
      (const folly::SocketAddress&, size_t, bool, OnDataAvailableParams));

  void onDataAvailable(
      const folly::SocketAddress& client,
      size_t len,
      bool truncated,
      OnDataAvailableParams params) noexcept override {
    try {
      onDataAvailable_(client, len, truncated, params);
    } catch (std::exception) {
      // Swallow exception from mock function to keep linter happy.
    }
  }

  MOCK_METHOD(void, onReadError_, (const folly::AsyncSocketException&));

  void onReadError(const folly::AsyncSocketException& ex) noexcept override {
    try {
      onReadError_(ex);
    } catch (std::exception) {
      // Swallow exception from mock function to keep linter happy.
    }
  }

  MOCK_METHOD(void, onReadClosed_, ());

  void onReadClosed() noexcept override {
    try {
      onReadClosed_();
    } catch (std::exception) {
      // Swallow exception from mock function to keep linter happy.
    }
  }
};

} // namespace quic::test
