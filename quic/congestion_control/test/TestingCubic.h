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
      uint64_t initCwndBytes = 0,
      uint64_t initSsthresh = Cubic::INIT_SSTHRESH,
      bool tcpFriendly = true,
      bool ackTrain = false,
      bool spreadAcrossRtt = false)
      : Cubic(
            conn,
            initCwndBytes,
            initSsthresh,
            tcpFriendly,
            ackTrain,
            spreadAcrossRtt) {}

  void setStateForTest(CubicStates state) {
    state_ = state;
  }
};

} // namespace test
} // namespace quic
