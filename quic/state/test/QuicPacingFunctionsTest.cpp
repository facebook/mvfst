/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/QuicPacingFunctions.h>

#include <folly/portability/GTest.h>

using namespace testing;

namespace quic {
namespace test {

class QuicPacingFunctionsTest : public Test {};

TEST_F(QuicPacingFunctionsTest, OnKeyEstablished) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  EXPECT_FALSE(conn.canBePaced);
  updatePacingOnKeyEstablished(conn);
  EXPECT_TRUE(conn.canBePaced);
}

TEST_F(QuicPacingFunctionsTest, OnClose) {
  QuicConnectionStateBase conn(QuicNodeType::Client);
  conn.canBePaced = true;
  updatePacingOnClose(conn);
  EXPECT_FALSE(conn.canBePaced);
}

} // namespace test
} // namespace quic
