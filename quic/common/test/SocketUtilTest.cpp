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
      void(const folly::SocketOptionMap&, folly::SocketOptionKey::ApplyPos));
};

TEST(SocketUtilTest, applySocketOptions) {
  MockQuicAsyncUDPSocket sock(nullptr);
  const folly::SocketOptionMap opts = {
      {{SOL_SOCKET, SO_KEEPALIVE, folly::SocketOptionKey::ApplyPos::POST_BIND},
       false},
      {{IPPROTO_TCP, TCP_MAXSEG, folly::SocketOptionKey::ApplyPos::POST_BIND},
       576},
      {{IPPROTO_UDP, TCP_MAXSEG, folly::SocketOptionKey::ApplyPos::POST_BIND},
       576},
#ifdef IP_BIND_ADDRESS_NO_PORT
      {{IPPROTO_IP,
        IP_BIND_ADDRESS_NO_PORT,
        folly::SocketOptionKey::ApplyPos::PRE_BIND},
       true},
#endif
      {{IPPROTO_IP, IP_TOS, folly::SocketOptionKey::ApplyPos::PRE_BIND}, 0x80},
      {{IPPROTO_IPV6, IPV6_TCLASS, folly::SocketOptionKey::ApplyPos::PRE_BIND},
       0x80},
  };

  const folly::SocketOptionMap expected_v4_prebind_opts = {
#ifdef IP_BIND_ADDRESS_NO_PORT
      {{IPPROTO_IP,
        IP_BIND_ADDRESS_NO_PORT,
        folly::SocketOptionKey::ApplyPos::PRE_BIND},
       true},
#endif
      {{IPPROTO_IP, IP_TOS, folly::SocketOptionKey::ApplyPos::PRE_BIND}, 0x80},
  };

  const folly::SocketOptionMap expected_v4_postbind_opts = {
      {{SOL_SOCKET, SO_KEEPALIVE, folly::SocketOptionKey::ApplyPos::POST_BIND},
       false},
      {{IPPROTO_UDP, TCP_MAXSEG, folly::SocketOptionKey::ApplyPos::POST_BIND},
       576},
  };

  const folly::SocketOptionMap expected_v6_prebind_opts = {
#ifdef IP_BIND_ADDRESS_NO_PORT
      {{IPPROTO_IP,
        IP_BIND_ADDRESS_NO_PORT,
        folly::SocketOptionKey::ApplyPos::PRE_BIND},
       true},
#endif
      {{IPPROTO_IPV6, IPV6_TCLASS, folly::SocketOptionKey::ApplyPos::PRE_BIND},
       0x80},
  };

  const folly::SocketOptionMap expected_v6_postbind_opts = {
      {{SOL_SOCKET, SO_KEEPALIVE, folly::SocketOptionKey::ApplyPos::POST_BIND},
       false},
      {{IPPROTO_UDP, TCP_MAXSEG, folly::SocketOptionKey::ApplyPos::POST_BIND},
       576},
  };

  EXPECT_CALL(
      sock,
      applyOptions(
          expected_v4_prebind_opts, folly::SocketOptionKey::ApplyPos::PRE_BIND))
      .Times(1);
  applySocketOptions(
      sock, opts, AF_INET, folly::SocketOptionKey::ApplyPos::PRE_BIND);
  EXPECT_CALL(
      sock,
      applyOptions(
          expected_v4_postbind_opts,
          folly::SocketOptionKey::ApplyPos::POST_BIND))
      .Times(1);
  applySocketOptions(
      sock, opts, AF_INET, folly::SocketOptionKey::ApplyPos::POST_BIND);
  EXPECT_CALL(
      sock,
      applyOptions(
          expected_v6_prebind_opts, folly::SocketOptionKey::ApplyPos::PRE_BIND))
      .Times(1);
  applySocketOptions(
      sock, opts, AF_INET6, folly::SocketOptionKey::ApplyPos::PRE_BIND);
  EXPECT_CALL(
      sock,
      applyOptions(
          expected_v6_postbind_opts,
          folly::SocketOptionKey::ApplyPos::POST_BIND))
      .Times(1);
  applySocketOptions(
      sock, opts, AF_INET6, folly::SocketOptionKey::ApplyPos::POST_BIND);
}
