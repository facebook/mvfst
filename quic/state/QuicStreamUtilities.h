/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>

namespace quic {

enum class StreamInitiator : uint8_t { Local, Remote };

enum class StreamDirectionality : uint8_t { Unidirectional, Bidirectional };

/**
 * Returns whether the given StreamId identifies a client stream.
 */
bool isClientStream(StreamId stream);

/**
 * Returns whether the given StreamId identifies a server stream.
 */
bool isServerStream(StreamId stream);

/**
 * Returns whether the given StreamId identifies a unidirectional stream.
 */
bool isUnidirectionalStream(StreamId stream);

/**
 * Returns whether the given StreamId identifies a bidirectional stream.
 */
bool isBidirectionalStream(StreamId stream);

/**
 * Returns whether the given StreamId identifies a client bidirectional stream.
 */
bool isClientBidirectionalStream(StreamId stream);

/**
 * Returns whether the given StreamId identifies a server unidirectional stream.
 */
bool isServerUnidirectionalStream(StreamId stream);

/**
 * Returns directionality (unidirectional or bidirectional) of a stream by ID.
 */
StreamDirectionality getStreamDirectionality(StreamId stream);

/**
 * Returns whether the given QuicNodeType and StreamId indicate a sending
 * stream, i.e., a stream which only sends data. Note that a bidirectional
 * stream is NOT considered a sending stream by this definition.
 */
bool isSendingStream(QuicNodeType nodeType, StreamId stream);

/**
 * Returns whether the given QuicNodeType and StreamId indicate a receiving
 * stream, i.e., a stream which only receives data. Note that a bidirectional
 * stream is NOT considered a receiving stream by this definition.
 */
bool isReceivingStream(QuicNodeType nodeType, StreamId stream);

/**
 * Returns whether the given QuicNodeType and StreamId indicates the stream is
 * a local stream (i.e. the stream initiator matches the node type).
 */
bool isLocalStream(QuicNodeType nodeType, StreamId stream);

/**
 * Returns whether the given QuicNodeType and StreamId indicates the stream is
 * a remote stream (i.e. the stream initiator doesn't match the node type).
 */
bool isRemoteStream(QuicNodeType nodeType, StreamId stream);

/**
 * Returns initiator (local or remote) of a stream by ID.
 */
StreamInitiator getStreamInitiator(QuicNodeType nodeType, StreamId stream);

} // namespace quic
