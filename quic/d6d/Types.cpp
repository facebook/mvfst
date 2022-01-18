/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/d6d/Types.h>

#include <folly/lang/Assume.h>

namespace quic {
std::string toString(const D6DMachineState state) {
  switch (state) {
    case D6DMachineState::DISABLED:
      return "DISABLED";
    case D6DMachineState::BASE:
      return "BASE";
    case D6DMachineState::SEARCHING:
      return "SEARCHING";
    case D6DMachineState::SEARCH_COMPLETE:
      return "SEARCH_COMPLETE";
    case D6DMachineState::ERROR:
      return "ERROR";
  }
  folly::assume_unreachable();
}

std::string toString(const ProbeSizeRaiserType type) {
  switch (type) {
    case ProbeSizeRaiserType::ConstantStep:
      return "ConstantStep";
    case ProbeSizeRaiserType::BinarySearch:
      return "BinarySearch";
  }
  folly::assume_unreachable();
}

} // namespace quic
