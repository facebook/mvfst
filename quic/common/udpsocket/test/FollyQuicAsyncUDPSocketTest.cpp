/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/common/udpsocket/test/QuicAsyncUDPSocketTestBase.h>

using namespace ::testing;

class FollyQuicAsyncUDPSocketProvider {
 public:
  static std::shared_ptr<quic::QuicAsyncUDPSocket> makeQuicAsyncUDPSocket() {
    static folly::EventBase fEvb;
    auto evb = std::make_shared<quic::FollyQuicEventBase>(&fEvb);
    return std::make_shared<quic::FollyQuicAsyncUDPSocket>(evb);
  }
};

using FollyQuicAsyncUDPSocketType = Types<FollyQuicAsyncUDPSocketProvider>;

INSTANTIATE_TYPED_TEST_SUITE_P(
    FollyQuicAsyncUDPSocketTest, // Instance name
    QuicAsyncUDPSocketTest, // Test case name
    FollyQuicAsyncUDPSocketType); // Type list
