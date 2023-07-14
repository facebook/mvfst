/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/json.h>
#include <quic/state/TransportSettings.h>

namespace quic {

void populateAckFrequencyConfig(
    const folly::dynamic& srcAckFrequencyConfigDyn,
    CongestionControlConfig& dstCcaConfig);

// Parses the JSON string into a CongestionControlConfig.
//  - Fields not present in the JSON string will use their default values
//  - Additional fields in the JSON string will be ignored
//  - Throws if parsing fails or fields have a wrong type
quic::CongestionControlConfig parseCongestionControlConfig(
    const std::string& ccaConfigJson);

// Same as parse function but returns folly::none on error instead of throwing.
folly::Optional<quic::CongestionControlConfig> tryParseCongestionControlConfig(
    const std::string& ccaConfigJson);
} // namespace quic
