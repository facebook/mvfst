/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/client/handshake/CachedServerTransportParametersSerialization.h>

#include <fizz/record/Types.h>
#include <fizz/util/Status.h>

namespace quic {

void writeCachedServerTransportParameters(
    const CachedServerTransportParameters& params,
    folly::io::Appender& appender) {
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.idleTimeout, appender), err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.maxRecvPacketSize, appender), err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.initialMaxData, appender), err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.initialMaxStreamDataBidiLocal, appender),
      err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.initialMaxStreamDataBidiRemote, appender),
      err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.initialMaxStreamDataUni, appender), err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.initialMaxStreamsBidi, appender), err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.initialMaxStreamsUni, appender), err);
  uint8_t knobSupport = params.knobFrameSupport ? 1 : 0;
  FIZZ_THROW_ON_ERROR(fizz::detail::write(err, knobSupport, appender), err);
  uint8_t ackReceiveTimestampsEnabled =
      params.ackReceiveTimestampsEnabled ? 1 : 0;
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, ackReceiveTimestampsEnabled, appender), err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.maxReceiveTimestampsPerAck, appender),
      err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.receiveTimestampsExponent, appender),
      err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::write(err, params.extendedAckFeatures, appender), err);
}

void readCachedServerTransportParameters(
    folly::io::Cursor& cursor,
    CachedServerTransportParameters& params) {
  size_t len;
  fizz::Error err;
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, params.idleTimeout, cursor), err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, params.maxRecvPacketSize, cursor), err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, params.initialMaxData, cursor), err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(
          len, err, params.initialMaxStreamDataBidiLocal, cursor),
      err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(
          len, err, params.initialMaxStreamDataBidiRemote, cursor),
      err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, params.initialMaxStreamDataUni, cursor),
      err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, params.initialMaxStreamsBidi, cursor), err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, params.initialMaxStreamsUni, cursor), err);
  uint8_t knobFrameSupport;
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, knobFrameSupport, cursor), err);
  params.knobFrameSupport = knobFrameSupport > 0;
  uint8_t ackReceiveTimestampsEnabled;
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, ackReceiveTimestampsEnabled, cursor), err);
  params.ackReceiveTimestampsEnabled = ackReceiveTimestampsEnabled > 0;
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, params.maxReceiveTimestampsPerAck, cursor),
      err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, params.receiveTimestampsExponent, cursor),
      err);
  FIZZ_THROW_ON_ERROR(
      fizz::detail::read(len, err, params.extendedAckFeatures, cursor), err);
}

std::unique_ptr<folly::IOBuf> serializeCachedServerTransportParameters(
    const CachedServerTransportParameters& params) {
  auto buf = folly::IOBuf::create(0);
  folly::io::Appender appender(buf.get(), 512);
  writeCachedServerTransportParameters(params, appender);
  return buf;
}

bool deserializeCachedServerTransportParameters(
    folly::ByteRange data,
    CachedServerTransportParameters& params) {
  if (data.empty()) {
    return false;
  }

  try {
    auto buf = folly::IOBuf::wrapBuffer(data);
    folly::io::Cursor cursor(buf.get());
    readCachedServerTransportParameters(cursor, params);
    return true;
  } catch (const std::exception&) {
    return false;
  }
}

} // namespace quic
