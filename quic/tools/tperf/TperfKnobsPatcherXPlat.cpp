/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/tools/tperf/TperfKnobsPatcher.h>

#include <quic/common/MvfstLogging.h>

namespace quic::tperf {

struct TperfKnobsPatcher::Impl {};

TperfKnobsPatcher::TperfKnobsPatcher() : impl_(std::make_unique<Impl>()) {}

TperfKnobsPatcher::~TperfKnobsPatcher() = default;

bool TperfKnobsPatcher::patch(std::string_view commaSeparatedKnobNames) {
  if (commaSeparatedKnobNames.empty()) {
    return true;
  }
  MVLOG_ERROR << "--jks_to_patch is only supported in fbcode Linux builds";
  return false;
}

} // namespace quic::tperf
