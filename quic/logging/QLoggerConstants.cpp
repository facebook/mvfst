/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/logging/QLoggerConstants.h>

namespace quic {
folly::StringPiece vantagePointString(VantagePoint vantagePoint) noexcept {
  switch (vantagePoint) {
    case VantagePoint::Client:
      return kQLogClientVantagePoint;
    case VantagePoint::Server:
      return kQLogServerVantagePoint;
  }
  folly::assume_unreachable();
}

folly::StringPiece toQlogString(FrameType frame) {
  switch (frame) {
    case FrameType::PADDING:
      return "padding";
    case FrameType::PING:
      return "ping";
    case FrameType::ACK:
      return "ack";
    case FrameType::ACK_ECN:
      return "ack_ecn";
    case FrameType::RST_STREAM:
      return "rst_stream";
    case FrameType::RST_STREAM_AT:
      return "rst_stream_at";
    case FrameType::STOP_SENDING:
      return "stop_sending";
    case FrameType::CRYPTO_FRAME:
      return "crypto";
    case FrameType::NEW_TOKEN:
      return "new_token";
    case FrameType::STREAM:
    case FrameType::STREAM_FIN:
    case FrameType::STREAM_LEN:
    case FrameType::STREAM_LEN_FIN:
    case FrameType::STREAM_OFF:
    case FrameType::STREAM_OFF_FIN:
    case FrameType::STREAM_OFF_LEN:
    case FrameType::STREAM_OFF_LEN_FIN:
      return "stream";
    case FrameType::MAX_DATA:
      return "max_data";
    case FrameType::MAX_STREAM_DATA:
      return "max_stream_data";
    case FrameType::MAX_STREAMS_BIDI:
    case FrameType::MAX_STREAMS_UNI:
      return "max_streams";
    case FrameType::DATA_BLOCKED:
      return "data_blocked";
    case FrameType::STREAM_DATA_BLOCKED:
      return "stream_data_blocked";
    case FrameType::STREAMS_BLOCKED_BIDI:
    case FrameType::STREAMS_BLOCKED_UNI:
      return "streams_blocked";
    case FrameType::NEW_CONNECTION_ID:
      return "new_connection_id";
    case FrameType::RETIRE_CONNECTION_ID:
      return "retire_connection_id";
    case FrameType::PATH_CHALLENGE:
      return "path_challenge";
    case FrameType::PATH_RESPONSE:
      return "path_response";
    case FrameType::CONNECTION_CLOSE:
    case FrameType::CONNECTION_CLOSE_APP_ERR:
      return "connection_close";
    case FrameType::HANDSHAKE_DONE:
      return "handshake_done";
    case FrameType::DATAGRAM:
    case FrameType::DATAGRAM_LEN:
      return "datagram";
    case FrameType::KNOB:
      return "knob";
    case FrameType::ACK_FREQUENCY:
      return "ack_frequency";
    case FrameType::IMMEDIATE_ACK:
      return "immediate_ack";
    case FrameType::ACK_RECEIVE_TIMESTAMPS:
      return "ack_receive_timestamps";
    case FrameType::ACK_EXTENDED:
      return "ack_extended";
    // Distinct qlog strings so legacy and draft-02 receive-timestamp ACKs
    // are not conflated. Draft-02 ranges use `draft02_timestamp_ranges`
    // with `delta_largest_acknowledged`; legacy uses `timestamp_ranges`
    // with `gap`.
    case FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02:
      return "ack_receive_timestamps_draft_02";
    case FrameType::ACK_RECEIVE_TIMESTAMPS_DRAFT_02_ECN:
      return "ack_receive_timestamps_draft_02_ecn";
  }
  folly::assume_unreachable();
}

folly::StringPiece toQlogString(LongHeader::Types type) {
  switch (type) {
    case LongHeader::Types::Initial:
      return "initial";
    case LongHeader::Types::Retry:
      return "RETRY";
    case LongHeader::Types::Handshake:
      return "handshake";
    case LongHeader::Types::ZeroRtt:
      return "0RTT";
  }
  folly::assume_unreachable();
}

} // namespace quic
