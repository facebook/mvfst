/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <ev.h>
#include <folly/portability/GTest.h>
#include <quic/common/events/LibevQuicEventBase.h>
#include <quic/common/events/test/QuicEventBaseTestBase.h>

using namespace ::testing;

class LibevQuicEventBaseProvider {
 public:
  static std::shared_ptr<quic::QuicEventBase> makeQuicEvb() {
    static struct ev_loop* evLoop = ev_loop_new(0);
    return std::make_shared<quic::LibevQuicEventBase>(evLoop);
  }
};

using LibevQuicEventBaseType = Types<LibevQuicEventBaseProvider>;

INSTANTIATE_TYPED_TEST_SUITE_P(
    LibevQuicEventBaseTest, // Instance name
    QuicEventBaseTest, // Test case name
    LibevQuicEventBaseType); // Type list
