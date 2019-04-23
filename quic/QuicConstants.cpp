/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/QuicConstants.h>

namespace quic {

QuicBatchingMode getQuicBatchingMode(uint32_t val) {
  switch (val) {
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_NONE):
      return QuicBatchingMode::BATCHING_MODE_NONE;
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_GSO):
      return QuicBatchingMode::BATCHING_MODE_GSO;
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_SENDMMSG):
      return QuicBatchingMode::BATCHING_MODE_SENDMMSG;
      // no default
  }

  return QuicBatchingMode::BATCHING_MODE_NONE;
}
std::vector<QuicVersion> filterSupportedVersions(
    const std::vector<QuicVersion>& versions) {
  std::vector<QuicVersion> filteredVersions;
  std::copy_if(
      versions.begin(),
      versions.end(),
      std::back_inserter(filteredVersions),
      [](auto version) {
        return version == QuicVersion::MVFST ||
            version == QuicVersion::QUIC_DRAFT ||
            version == QuicVersion::MVFST_INVALID;
      });
  return filteredVersions;
}
} // namespace quic
