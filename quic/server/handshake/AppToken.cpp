/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/server/handshake/AppToken.h>

#include <quic/QuicConstants.h>
#include <quic/handshake/TransportParameters.h>

#include <fizz/record/Types.h>
#include <folly/IPAddress.h>
#include <folly/Optional.h>
#include <folly/io/Cursor.h>
#include <folly/io/IOBuf.h>

#include <glog/logging.h>

#include <cstdint>
#include <memory>
#include <vector>

namespace quic {

TicketTransportParameters createTicketTransportParameters(
    uint64_t idleTimeout,
    uint64_t maxRecvPacketSize,
    uint64_t initialMaxData,
    uint64_t initialMaxStreamDataBidiLocal,
    uint64_t initialMaxStreamDataBidiRemote,
    uint64_t initialMaxStreamDataUni,
    uint64_t initialMaxStreamsBidi,
    uint64_t initialMaxStreamsUni) {
  TicketTransportParameters params;
  params.parameters.push_back(
      encodeIntegerParameter(TransportParameterId::idle_timeout, idleTimeout));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::max_packet_size, maxRecvPacketSize));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_data, initialMaxData));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_local,
      initialMaxStreamDataBidiLocal));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_bidi_remote,
      initialMaxStreamDataBidiRemote));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_stream_data_uni,
      initialMaxStreamDataUni));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_streams_bidi, initialMaxStreamsBidi));
  params.parameters.push_back(encodeIntegerParameter(
      TransportParameterId::initial_max_streams_uni, initialMaxStreamsUni));
  return params;
}

fizz::Buf encodeAppToken(const AppToken& appToken) {
  auto buf = folly::IOBuf::create(20);
  folly::io::Appender appender(buf.get(), 20);
  auto ext = encodeExtension(appToken.transportParams);
  fizz::detail::write(ext, appender);
  fizz::detail::writeVector<uint8_t>(appToken.sourceAddresses, appender);
  if (appToken.version) {
    fizz::detail::write(appToken.version.value(), appender);
  }
  fizz::detail::writeBuf<uint16_t>(appToken.appParams, appender);
  return buf;
}

folly::Optional<AppToken> decodeAppToken(const folly::IOBuf& buf) {
  AppToken appToken;
  folly::io::Cursor cursor(&buf);
  std::vector<fizz::Extension> extensions;
  fizz::Extension ext;
  try {
    fizz::detail::read(ext, cursor);
    extensions.push_back(std::move(ext));
    appToken.transportParams =
        *fizz::getExtension<TicketTransportParameters>(extensions);
    fizz::detail::readVector<uint8_t>(appToken.sourceAddresses, cursor);
    if (cursor.isAtEnd()) {
      return appToken;
    }
    QuicVersion v{QuicVersion::MVFST_INVALID};
    fizz::detail::read(v, cursor);
    appToken.version = v;
    fizz::detail::readBuf<uint16_t>(appToken.appParams, cursor);
  } catch (const std::exception& ex) {
    return folly::none;
  }
  return appToken;
}

} // namespace quic
