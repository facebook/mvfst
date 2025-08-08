/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GTest.h>
#include <quic/common/udpsocket/test/QuicAsyncUDPSocketMock.h>

template <class T>
class QuicAsyncUDPSocketTestBase : public testing::Test {
 public:
  void SetUp() override {
    udpSocket_ = T::makeQuicAsyncUDPSocket();

    // For QUIC, we're only interested in the shouldOnlyNotify path.
    EXPECT_CALL(readCb_, shouldOnlyNotify())
        .WillRepeatedly(testing::Return(true));
  }

 protected:
  quic::test::MockErrMessageCallback errCb_;
  quic::test::MockUDPReadCallback readCb_;
  std::shared_ptr<quic::QuicAsyncUDPSocket> udpSocket_;
};

template <class T>
class QuicAsyncUDPSocketTest : public QuicAsyncUDPSocketTestBase<T> {};

TYPED_TEST_SUITE_P(QuicAsyncUDPSocketTest);

// Tests start here

TYPED_TEST_P(QuicAsyncUDPSocketTest, ErrToNonExistentServer) {
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  ASSERT_FALSE(
      this->udpSocket_->bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  this->udpSocket_->resumeRead(&this->readCb_);
  ASSERT_FALSE(
      this->udpSocket_->setErrMessageCallback(&this->errCb_).hasError());

  folly::SocketAddress addr("127.0.0.1", 10000);
  bool errRecvd = false;

  // Expect an ICMP error
  EXPECT_CALL(this->errCb_, errMessage_(testing::_))
      .WillOnce(testing::Invoke([this, &errRecvd](auto& cmsg) {
        if ((cmsg.cmsg_level == SOL_IP && cmsg.cmsg_type == IP_RECVERR) ||
            (cmsg.cmsg_level == SOL_IPV6 && cmsg.cmsg_type == IPV6_RECVERR)) {
          const auto* serr = reinterpret_cast<const struct sock_extended_err*>(
              CMSG_DATA(&cmsg));
          errRecvd =
              (serr->ee_origin == SO_EE_ORIGIN_ICMP || SO_EE_ORIGIN_ICMP6);
        }
        this->udpSocket_->getEventBase()->terminateLoopSoon();
      }));

  // If an error is received, the read callback should not be triggered
  EXPECT_CALL(this->readCb_, onNotifyDataAvailable_(testing::_)).Times(0);

  auto sendBuf = quic::BufHelpers::copyBuffer("hey");
  iovec vec[quic::kNumIovecBufferChains];
  size_t iovec_len =
      sendBuf->fillIov(vec, sizeof(vec) / sizeof(vec[0])).numIovecs;
  this->udpSocket_->write(addr, vec, iovec_len);
  this->udpSocket_->getEventBase()->loopForever();
  EXPECT_TRUE(errRecvd);
#else // !FOLLY_HAVE_MSG_ERRQUEUE
  GTEST_SKIP();
#endif
}

TYPED_TEST_P(QuicAsyncUDPSocketTest, TestUnsetErrCallback) {
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  ASSERT_FALSE(
      this->udpSocket_->bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  this->udpSocket_->resumeRead(&this->readCb_);
  ASSERT_FALSE(
      this->udpSocket_->setErrMessageCallback(&this->errCb_).hasError());
  ASSERT_FALSE(this->udpSocket_->setErrMessageCallback(nullptr).hasError());
  folly::SocketAddress addr("127.0.0.1", 10000);
  EXPECT_CALL(this->errCb_, errMessage_(testing::_)).Times(0);
  EXPECT_CALL(this->readCb_, onNotifyDataAvailable_(testing::_)).Times(0);

  auto sendBuf = quic::BufHelpers::copyBuffer("hey");
  iovec vec[quic::kNumIovecBufferChains];
  size_t iovec_len =
      sendBuf->fillIov(vec, sizeof(vec) / sizeof(vec[0])).numIovecs;
  this->udpSocket_->write(addr, vec, iovec_len);

  class EvbTerminateTimeout : public quic::QuicTimerCallback {
   public:
    explicit EvbTerminateTimeout(quic::QuicEventBase* evb) : evb_(evb) {}

    void timeoutExpired() noexcept override {
      evb_->terminateLoopSoon();
    }

   private:
    quic::QuicEventBase* evb_;
  };

  auto evb = this->udpSocket_->getEventBase();

  auto timeout = std::make_unique<EvbTerminateTimeout>(evb.get());
  evb->scheduleTimeout(timeout.get(), std::chrono::milliseconds(30));
  evb->loopForever();
#else // !FOLLY_HAVE_MSG_ERRQUEUE
  GTEST_SKIP();
#endif
}

TYPED_TEST_P(QuicAsyncUDPSocketTest, CloseInErrorCallback) {
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  ASSERT_FALSE(
      this->udpSocket_->bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  this->udpSocket_->resumeRead(&this->readCb_);
  ASSERT_FALSE(
      this->udpSocket_->setErrMessageCallback(&this->errCb_).hasError());

  folly::SocketAddress addr("127.0.0.1", 10000);
  bool errRecvd = false;
  auto evb = this->udpSocket_->getEventBase();

  // Expect an error and close the socket in it.
  EXPECT_CALL(this->errCb_, errMessage_(testing::_))
      .WillOnce(testing::Invoke([this, &errRecvd, &evb](auto&) {
        errRecvd = true;
        ASSERT_FALSE(this->udpSocket_->close().hasError());
        evb->terminateLoopSoon();
      }));

  // Since the socket is closed by the error callback, the read callback
  // should not be triggered
  EXPECT_CALL(this->readCb_, onNotifyDataAvailable_(testing::_)).Times(0);
  auto sendBuf = quic::BufHelpers::copyBuffer("hey");
  iovec vec[quic::kNumIovecBufferChains];
  size_t iovec_len =
      sendBuf->fillIov(vec, sizeof(vec) / sizeof(vec[0])).numIovecs;
  this->udpSocket_->write(addr, vec, iovec_len);
  this->udpSocket_->getEventBase()->loopForever();
  EXPECT_TRUE(errRecvd);
#else // !FOLLY_HAVE_MSG_ERRQUEUE
  GTEST_SKIP();
#endif
}

TYPED_TEST_P(QuicAsyncUDPSocketTest, ConnectMarksSocketBoundIPv4) {
  auto connectAddress = folly::SocketAddress("127.0.0.1", 10000);
  ASSERT_FALSE(this->udpSocket_->connect(connectAddress).hasError());

  EXPECT_TRUE(this->udpSocket_->isBound());

  auto localAddressResult = this->udpSocket_->address();
  ASSERT_FALSE(localAddressResult.hasError());

  auto addrFamilyResult = this->udpSocket_->getLocalAddressFamily();
  ASSERT_FALSE(this->udpSocket_->getLocalAddressFamily().hasError());
  EXPECT_EQ(addrFamilyResult.value(), AF_INET);
}

TYPED_TEST_P(QuicAsyncUDPSocketTest, ConnectMarksSocketBoundIPv6) {
  auto connectAddress = folly::SocketAddress("::1", 10000);
  ASSERT_FALSE(this->udpSocket_->connect(connectAddress).hasError());

  EXPECT_TRUE(this->udpSocket_->isBound());

  auto localAddressResult = this->udpSocket_->address();
  ASSERT_FALSE(localAddressResult.hasError());

  auto addrFamilyResult = this->udpSocket_->getLocalAddressFamily();
  ASSERT_FALSE(this->udpSocket_->getLocalAddressFamily().hasError());
  EXPECT_EQ(addrFamilyResult.value(), AF_INET6);
}

// Tests end here

// All tests must be registered
REGISTER_TYPED_TEST_SUITE_P(
    QuicAsyncUDPSocketTest,
    ErrToNonExistentServer,
    TestUnsetErrCallback,
    CloseInErrorCallback,
    ConnectMarksSocketBoundIPv4,
    ConnectMarksSocketBoundIPv6
    // Add more tests here
);
