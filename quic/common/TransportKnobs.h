/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once
#include <folly/Optional.h>
#include <string>
#include <unordered_map>
#include <variant>
#include <vector>

namespace quic {

/**
 * This is not to be confused with the structure of knob frame, or QUIC's
 * transport parameter. Knob frame has space, id and a blob. Arbitrary data can
 * be stored in the blob. TransportKnobParam is a kind of blob that designated
 * to pass transport-level parameter that's no transferable via existing
 * methods (e.g. transport parameter).
 */
struct TransportKnobParam {
  using Val = std::variant<uint64_t, std::string>;
  uint64_t id;
  Val val;
};

constexpr uint64_t kPriorityThresholdKnobMultiplier = 1000;

using TransportKnobParams = std::vector<TransportKnobParam>;

folly::Optional<TransportKnobParams> parseTransportKnobs(
    const std::string& serializedParams);

} // namespace quic
