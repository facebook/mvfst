/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <ev.h>
#include <folly/portability/GTest.h>
#include <quic/common/udpsocket/LibevQuicAsyncUDPSocket.h>
#include <quic/common/udpsocket/test/QuicAsyncUDPSocketTestBase.h>

using namespace ::testing;

class LibevQuicAsyncUDPSocketProvider {
 public:
  static std::shared_ptr<quic::QuicAsyncUDPSocket> makeQuicAsyncUDPSocket() {
    static struct ev_loop* evLoop = ev_loop_new(0);
    auto evb = std::make_shared<quic::LibevQuicEventBase>(evLoop);
    return std::make_shared<quic::LibevQuicAsyncUDPSocket>(evb);
  }
};

using LibevQuicAsyncUDPSocketType = Types<LibevQuicAsyncUDPSocketProvider>;

INSTANTIATE_TYPED_TEST_SUITE_P(
    LibevQuicAsyncUDPSocketTest, // Instance name
    QuicAsyncUDPSocketTest, // Test case name
    LibevQuicAsyncUDPSocketType); // Type list
