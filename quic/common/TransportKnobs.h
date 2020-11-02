// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once
#include <folly/Optional.h>
#include <string>
#include <unordered_map>
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
  uint64_t id;
  uint64_t val;
};

using TransportKnobParams = std::vector<TransportKnobParam>;

folly::Optional<TransportKnobParams> parseTransportKnobs(
    const std::string& serializedParams);

} // namespace quic
