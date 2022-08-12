/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/dsr/Types.h>

namespace quic {
WriteStreamFrame sendInstructionToWriteStreamFrame(
    const SendInstruction& sendInstruction) {
  WriteStreamFrame frame(
      sendInstruction.streamId,
      sendInstruction.streamOffset,
      sendInstruction.len,
      sendInstruction.fin);
  frame.fromBufMeta = true;
  return frame;
}
} // namespace quic
