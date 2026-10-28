/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/EventBaseBackendBase.h>

namespace quic {

struct EventBaseBackendDetails {
  std::unique_ptr<folly::EventBaseBackendBase> (*factory)();
};

// Platform-selected EventBase backend for standalone server threads.
EventBaseBackendDetails getEventBaseBackendDetails();

} // namespace quic
