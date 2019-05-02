/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/congestion_control/QuicCubic.h>

namespace quic {
namespace test {

class TestingCubic : public Cubic {
 public:
  TestingCubic(
      QuicConnectionStateBase& conn,
      uint64_t initSsthresh = std::numeric_limits<uint64_t>::max(),
      bool tcpFriendly = true,
      bool ackTrain = false,
      bool spreadAcrossRtt = false)
      : Cubic(conn, initSsthresh, tcpFriendly, ackTrain, spreadAcrossRtt) {}

  void setStateForTest(CubicStates state) {
    state_ = state;
  }
};

} // namespace test
} // namespace quic
