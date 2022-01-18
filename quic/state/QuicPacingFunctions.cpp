/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/QuicPacingFunctions.h>

namespace quic {

void updatePacingOnKeyEstablished(QuicConnectionStateBase& conn) {
  conn.canBePaced = true;
}

void updatePacingOnClose(QuicConnectionStateBase& conn) {
  conn.canBePaced = false;
}

} // namespace quic
