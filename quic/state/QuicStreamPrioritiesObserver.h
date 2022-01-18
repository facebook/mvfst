/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

namespace quic {

class QuicStreamPrioritiesObserver {
 public:
  virtual ~QuicStreamPrioritiesObserver() = default;

  virtual void onStreamPrioritiesChange() = 0;
};

} // namespace quic
