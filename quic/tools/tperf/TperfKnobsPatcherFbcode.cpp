/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/tools/tperf/TperfKnobsPatcher.h>

#include <exception>
#include <string>
#include <vector>

#include <folly/String.h>
#include <justknobs/TestHelpers.h>
#include <quic/common/MvfstLogging.h>

namespace quic::tperf {

struct TperfKnobsPatcher::Impl {
  facebook::jk::shim::PatchJustKnobs patcher;
  std::vector<std::unique_ptr<facebook::jk::shim::JustKnobsPatchState>> patches;
};

TperfKnobsPatcher::TperfKnobsPatcher() : impl_(std::make_unique<Impl>()) {}

TperfKnobsPatcher::~TperfKnobsPatcher() = default;

bool TperfKnobsPatcher::patch(std::string_view commaSeparatedKnobNames) {
  if (commaSeparatedKnobNames.empty()) {
    return true;
  }

  std::vector<std::string> knobNames;
  folly::split(
      ',',
      folly::StringPiece(
          commaSeparatedKnobNames.data(), commaSeparatedKnobNames.size()),
      knobNames,
      true);
  try {
    for (const auto& knobName : knobNames) {
      MVLOG_INFO << "Patching JK to true: " << knobName;
      impl_->patches.push_back(impl_->patcher.patch(knobName, true));
    }
  } catch (const std::exception& ex) {
    MVLOG_ERROR << "Failed to patch JustKnob: " << ex.what();
    return false;
  }
  return true;
}

} // namespace quic::tperf
