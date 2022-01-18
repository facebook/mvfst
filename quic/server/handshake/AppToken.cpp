/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/handshake/AppToken.h>

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

} // namespace quic
