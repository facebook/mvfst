/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/QuicPriorityQueue.h>

namespace quic {

/**
 * Default priority, urgency = 3, incremental = true
 * Note this is different from the priority draft where default incremental = 0
 */
const Priority kDefaultPriority(3, true);

} // namespace quic
