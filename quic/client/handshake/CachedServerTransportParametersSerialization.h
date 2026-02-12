/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/client/handshake/CachedServerTransportParameters.h>

#include <folly/Range.h>
#include <folly/io/Cursor.h>
#include <folly/io/IOBuf.h>

namespace quic {

/**
 * Serializes CachedServerTransportParameters to an appender.
 *
 * This allows the caller to continue writing additional data after
 * the transport parameters (e.g., appParams in proxygen).
 *
 * @param params The transport parameters to serialize.
 * @param appender The appender to write to.
 */
void writeCachedServerTransportParameters(
    const CachedServerTransportParameters& params,
    folly::io::Appender& appender);

/**
 * Deserializes CachedServerTransportParameters from a cursor.
 *
 * This allows the caller to continue reading additional data after
 * the transport parameters (e.g., appParams in proxygen).
 *
 * @param cursor The cursor to read from.
 * @param params The output CachedServerTransportParameters struct.
 */
void readCachedServerTransportParameters(
    folly::io::Cursor& cursor,
    CachedServerTransportParameters& params);

/**
 * Serializes CachedServerTransportParameters to a new IOBuf.
 *
 * Convenience wrapper around writeCachedServerTransportParameters.
 *
 * @param params The transport parameters to serialize.
 * @return A unique_ptr to an IOBuf containing the serialized data.
 */
std::unique_ptr<folly::IOBuf> serializeCachedServerTransportParameters(
    const CachedServerTransportParameters& params);

/**
 * Deserializes CachedServerTransportParameters from binary data.
 *
 * Convenience wrapper around readCachedServerTransportParameters.
 *
 * @param data The binary data to deserialize.
 * @param params The output CachedServerTransportParameters struct.
 * @return true if deserialization succeeded, false otherwise.
 */
bool deserializeCachedServerTransportParameters(
    folly::ByteRange data,
    CachedServerTransportParameters& params);

} // namespace quic
