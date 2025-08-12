/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <gmock/gmock.h>
#include <quic/common/SocketUtil.h>
#include <quic/common/events/FollyQuicEventBase.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>

class MockQuicAsyncUDPSocket : public quic::FollyQuicAsyncUDPSocket {
 public:
  explicit MockQuicAsyncUDPSocket(std::shared_ptr<quic::FollyQuicEventBase> evb)
      : quic::FollyQuicAsyncUDPSocket(evb) {}

  MOCK_METHOD2(
      applyOptions,
      quic::Expected<void, quic::QuicError>(
          const folly::SocketOptionMap&,
          folly::SocketOptionKey::ApplyPos));
};

TEST(SocketUtilTest, applySocketOptions) {
  MockQuicAsyncUDPSocket sock(nullptr);
  const folly::SocketOptionMap opts = {
      {{.level = SOL_SOCKET,
        .optname = SO_KEEPALIVE,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::POST_BIND},
       false},
      {{.level = IPPROTO_TCP,
        .optname = TCP_MAXSEG,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::POST_BIND},
       576},
      {{.level = IPPROTO_UDP,
        .optname = TCP_MAXSEG,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::POST_BIND},
       576},
#ifdef IP_BIND_ADDRESS_NO_PORT
      {{.level = IPPROTO_IP,
        .optname = IP_BIND_ADDRESS_NO_PORT,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::PRE_BIND},
       true},
#endif
      {{.level = IPPROTO_IP,
        .optname = IP_TOS,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::PRE_BIND},
       0x80},
      {{.level = IPPROTO_IPV6,
        .optname = IPV6_TCLASS,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::PRE_BIND},
       0x80},
  };

  const folly::SocketOptionMap expected_v4_prebind_opts = {
#ifdef IP_BIND_ADDRESS_NO_PORT
      {{.level = IPPROTO_IP,
        .optname = IP_BIND_ADDRESS_NO_PORT,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::PRE_BIND},
       true},
#endif
      {{.level = IPPROTO_IP,
        .optname = IP_TOS,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::PRE_BIND},
       0x80},
  };

  const folly::SocketOptionMap expected_v4_postbind_opts = {
      {{.level = SOL_SOCKET,
        .optname = SO_KEEPALIVE,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::POST_BIND},
       false},
      {{.level = IPPROTO_UDP,
        .optname = TCP_MAXSEG,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::POST_BIND},
       576},
  };

  const folly::SocketOptionMap expected_v6_prebind_opts = {
#ifdef IP_BIND_ADDRESS_NO_PORT
      {{.level = IPPROTO_IP,
        .optname = IP_BIND_ADDRESS_NO_PORT,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::PRE_BIND},
       true},
#endif
      {{.level = IPPROTO_IPV6,
        .optname = IPV6_TCLASS,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::PRE_BIND},
       0x80},
  };

  const folly::SocketOptionMap expected_v6_postbind_opts = {
      {{.level = SOL_SOCKET,
        .optname = SO_KEEPALIVE,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::POST_BIND},
       false},
      {{.level = IPPROTO_UDP,
        .optname = TCP_MAXSEG,
        .applyPos_ = folly::SocketOptionKey::ApplyPos::POST_BIND},
       576},
  };
  EXPECT_CALL(
      sock,
      applyOptions(
          expected_v4_prebind_opts, folly::SocketOptionKey::ApplyPos::PRE_BIND))
      .WillOnce(testing::Return(quic::Expected<void, quic::QuicError>{}));
  auto result1 = applySocketOptions(
      sock, opts, AF_INET, folly::SocketOptionKey::ApplyPos::PRE_BIND);
  EXPECT_CALL(
      sock,
      applyOptions(
          expected_v4_postbind_opts,
          folly::SocketOptionKey::ApplyPos::POST_BIND))
      .WillOnce(testing::Return(quic::Expected<void, quic::QuicError>{}));
  auto result2 = applySocketOptions(
      sock, opts, AF_INET, folly::SocketOptionKey::ApplyPos::POST_BIND);
  EXPECT_CALL(
      sock,
      applyOptions(
          expected_v6_prebind_opts, folly::SocketOptionKey::ApplyPos::PRE_BIND))
      .WillOnce(testing::Return(quic::Expected<void, quic::QuicError>{}));
  auto result3 = applySocketOptions(
      sock, opts, AF_INET6, folly::SocketOptionKey::ApplyPos::PRE_BIND);
  EXPECT_CALL(
      sock,
      applyOptions(
          expected_v6_postbind_opts,
          folly::SocketOptionKey::ApplyPos::POST_BIND))
      .WillOnce(testing::Return(quic::Expected<void, quic::QuicError>{}));
  auto result4 = applySocketOptions(
      sock, opts, AF_INET6, folly::SocketOptionKey::ApplyPos::POST_BIND);
}
