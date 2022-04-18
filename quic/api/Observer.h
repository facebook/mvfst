/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/observer/SocketObserverContainer.h>

namespace quic {

/**
 * Legacy observer of socket events.
 *
 * TODO(bschlinker): Complete depreciation.
 */
using LegacyObserver = SocketObserverContainer::LegacyObserver;

} // namespace quic
