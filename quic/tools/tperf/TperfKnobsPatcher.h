/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <memory>
#include <string_view>

namespace quic::tperf {

class TperfKnobsPatcher {
 public:
  TperfKnobsPatcher();
  ~TperfKnobsPatcher();

  TperfKnobsPatcher(const TperfKnobsPatcher&) = delete;
  TperfKnobsPatcher& operator=(const TperfKnobsPatcher&) = delete;
  TperfKnobsPatcher(TperfKnobsPatcher&&) = delete;
  TperfKnobsPatcher& operator=(TperfKnobsPatcher&&) = delete;

  bool patch(std::string_view commaSeparatedKnobNames);

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace quic::tperf
