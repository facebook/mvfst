/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/state/QuicStreamUtilities.h>
#include <quic/state/StateData.h>

namespace quic {

bool isServerStream(StreamId stream) {
  return stream & 0b01;
}

bool isClientStream(StreamId stream) {
  return (stream & 0b01) == 0;
}

bool isUnidirectionalStream(StreamId stream) {
  return stream & 0b10;
}

bool isBidirectionalStream(StreamId stream) {
  return !isUnidirectionalStream(stream);
}

bool isSendingStream(QuicNodeType nodeType, StreamId stream) {
  return isUnidirectionalStream(stream) &&
      ((nodeType == QuicNodeType::Client && isClientStream(stream)) ||
       (nodeType == QuicNodeType::Server && isServerStream(stream)));
}

bool isReceivingStream(QuicNodeType nodeType, StreamId stream) {
  return isUnidirectionalStream(stream) &&
      ((nodeType == QuicNodeType::Client && isServerStream(stream)) ||
       (nodeType == QuicNodeType::Server && isClientStream(stream)));
}

bool isLocalStream(QuicNodeType nodeType, StreamId stream) {
  return (nodeType == QuicNodeType::Client && isClientStream(stream)) ||
      (nodeType == QuicNodeType::Server && isServerStream(stream));
}

bool isRemoteStream(QuicNodeType nodeType, StreamId stream) {
  return (nodeType == QuicNodeType::Client && isServerStream(stream)) ||
      (nodeType == QuicNodeType::Server && isClientStream(stream));
}
} // namespace quic
