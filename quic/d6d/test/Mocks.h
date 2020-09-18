/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/d6d/ProbeSizeRaiser.h>

namespace quic {
namespace test {

// Mock
class MockProbeSizeRaiser : public ProbeSizeRaiser {
 public:
  ~MockProbeSizeRaiser() override {}

  MOCK_METHOD1(onProbeLost, void(uint16_t lastProbeSize));
  MOCK_METHOD1(
      raiseProbeSize,
      folly::Optional<uint16_t>(uint16_t lastProbeSize));
};

} // namespace test
} // namespace quic
