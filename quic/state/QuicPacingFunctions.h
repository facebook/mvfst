/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/state/StateData.h>

namespace quic {

void updatePacingOnKeyEstablished(QuicConnectionStateBase& conn);

void updatePacingOnClose(QuicConnectionStateBase& conn);

} // namespace quic
