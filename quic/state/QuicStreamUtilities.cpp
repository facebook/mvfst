/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/QuicStreamUtilities.h>

namespace quic {

bool isServerStream(StreamId stream) noexcept {
  return stream & 0b01;
}

bool isClientStream(StreamId stream) noexcept {
  return !isServerStream(stream);
}

bool isUnidirectionalStream(StreamId stream) noexcept {
  return stream & 0b10;
}

bool isBidirectionalStream(StreamId stream) noexcept {
  return !isUnidirectionalStream(stream);
}

bool isClientBidirectionalStream(StreamId streamId) noexcept {
  return isClientStream(streamId) && isBidirectionalStream(streamId);
}

bool isServerUnidirectionalStream(StreamId streamId) noexcept {
  return isServerStream(streamId) && isUnidirectionalStream(streamId);
}

StreamDirectionality getStreamDirectionality(StreamId stream) noexcept {
  return isUnidirectionalStream(stream) ? StreamDirectionality::Unidirectional
                                        : StreamDirectionality::Bidirectional;
}

bool isSendingStream(QuicNodeType nodeType, StreamId stream) noexcept {
  return isUnidirectionalStream(stream) && isLocalStream(nodeType, stream);
}

bool isReceivingStream(QuicNodeType nodeType, StreamId stream) noexcept {
  return isUnidirectionalStream(stream) && isRemoteStream(nodeType, stream);
}

// invariants should never be changed
static_assert(uint8_t(QuicNodeType::Client) == 0);
static_assert(uint8_t(QuicNodeType::Server) == 1);

bool isLocalStream(QuicNodeType nodeType, StreamId stream) noexcept {
  return (stream & 0x01) == uint8_t(nodeType);
}

bool isRemoteStream(QuicNodeType nodeType, StreamId stream) noexcept {
  return !isLocalStream(nodeType, stream);
}

StreamInitiator getStreamInitiator(
    QuicNodeType nodeType,
    StreamId id) noexcept {
  return isLocalStream(nodeType, id) ? StreamInitiator::Local
                                     : StreamInitiator::Remote;
}

} // namespace quic
