// (c) Facebook, Inc. and its affiliates. Confidential and proprietary.

#include "quic/state/QuicPriorityQueue.h"

namespace quic {

/**
 * Default priority, urgency = 3, incremental = true
 * Note this is different from the priority draft where default incremental = 0
 */
const Priority kDefaultPriority(3, true);

} // namespace quic
