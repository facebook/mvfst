/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/observer/SocketObserverContainer.h>
#include <quic/observer/SocketObserverInterface.h>

// Enables observer-only members in the real build (see
// QuicClientTransportLite). Preprocessor sentinel (used in #if), so it must
// stay a macro.
// NOLINTNEXTLINE(modernize-macro-to-enum)
#define QUIC_SOCKET_OBSERVERS_ENABLED 1

namespace quic {

// Guard macro for observer events with specific event type filtering.
// On mobile builds, this expands to if (false), eliminating the entire block.
#define SOCKET_OBSERVER_IF(container, event) \
  if ((container) && (container)->hasObserversForEvent<event>())

// Guard macro for observer events without event filtering (all observers).
// On mobile builds, this expands to if (false), eliminating the entire block.
#define SOCKET_OBSERVER_IF_ANY(container) if (container)

} // namespace quic
