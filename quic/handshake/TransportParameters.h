/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/Types.h>

namespace quic {

// macro for repetitive static_cast<uint64_t>(TransportParameterId)
#define u64_tp(tp_id) static_cast<uint64_t>(tp_id)

enum class TransportParameterId : uint64_t {
  original_destination_connection_id = 0x0000,
  idle_timeout = 0x0001,
  stateless_reset_token = 0x0002,
  max_packet_size = 0x0003,
  initial_max_data = 0x0004,
  initial_max_stream_data_bidi_local = 0x0005,
  initial_max_stream_data_bidi_remote = 0x0006,
  initial_max_stream_data_uni = 0x0007,
  initial_max_streams_bidi = 0x0008,
  initial_max_streams_uni = 0x0009,
  ack_delay_exponent = 0x000a,
  max_ack_delay = 0x000b,
  disable_migration = 0x000c,
  preferred_address = 0x000d,
  active_connection_id_limit = 0x000e,
  initial_source_connection_id = 0x000f,
  retry_source_connection_id = 0x0010,
  max_datagram_frame_size = 0x0020,
  min_ack_delay = 0xff04de1a,
  ack_receive_timestamps_enabled = 0xff0a001,
  max_receive_timestamps_per_ack = 0xff0a002,
  receive_timestamps_exponent = 0xff0a003,
  stream_groups_enabled = 0x0000ff99,
  knob_frames_supported = 0x00005178,
  cwnd_hint_bytes = 0x00007492
};

struct TransportParameter {
  TransportParameterId parameter;
  Buf value;

  TransportParameter() = default;

  TransportParameter(TransportParameterId p, Buf v)
      : parameter(p), value(v ? std::move(v) : nullptr) {}

  TransportParameter(const TransportParameter& other)
      : parameter(other.parameter),
        value(other.value ? other.value->clone() : nullptr) {}

  TransportParameter& operator=(TransportParameter&& other) noexcept {
    parameter = other.parameter;
    value = std::move(other.value);
    return *this;
  }

  /**
   * RFC9000:
   * Each transport parameter is encoded as an (identifier, length, value)
   * tuple:
   *
   *  Transport Parameter {
   *    Transport Parameter ID (i),
   *    Transport Parameter Length (i),
   *    Transport Parameter Value (..),
   *  }
   */

  // calc size needed to encode TransportParameter on the wire as shown above
  uint64_t getEncodedSize() const {
    // varint size of param + varint size of value's length + size of value
    uint64_t valueLen = value->computeChainDataLength();
    return getQuicIntegerSize(u64_tp(parameter)).value() +
        getQuicIntegerSize(valueLen).value() + valueLen;
  }

  // Encodes TransportParameter as shown above (avoids reallocations)
  Buf encode() const {
    // reserve the exact size needed
    auto res =
        folly::IOBuf::createCombined(static_cast<size_t>(getEncodedSize()));

    // write parameter; need to improve QuicInteger encoding methods
    BufWriter writer(*res, res->capacity());
    auto appenderOp = [&](auto val) { writer.writeBE(val); };
    CHECK(encodeQuicInteger(u64_tp(parameter), appenderOp));

    // write size of value
    CHECK(encodeQuicInteger(value->computeChainDataLength(), appenderOp));

    // write value if present
    if (value) {
      writer.insert(value.get());
    }

    return res;
  }
};

struct ClientTransportParameters {
  std::vector<TransportParameter> parameters;
};

struct ServerTransportParameters {
  std::vector<TransportParameter> parameters;
};

struct TicketTransportParameters {
  std::vector<TransportParameter> parameters;
};

inline auto findParameter(
    const std::vector<TransportParameter>& parameters,
    TransportParameterId id) {
  return std::find_if(parameters.begin(), parameters.end(), [id](auto& param) {
    return param.parameter == id;
  });
}

Optional<uint64_t> getIntegerParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters);

Optional<ConnectionId> getConnIdParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters);

Optional<StatelessResetToken> getStatelessResetTokenParameter(
    const std::vector<TransportParameter>& parameters);

TransportParameter encodeIntegerParameter(
    TransportParameterId id,
    uint64_t value);

inline TransportParameter encodeEmptyParameter(TransportParameterId id) {
  TransportParameter param;
  param.parameter = id;
  param.value = folly::IOBuf::create(0);
  return param;
}

inline TransportParameter encodeConnIdParameter(
    TransportParameterId id,
    const ConnectionId& connId) {
  return {id, folly::IOBuf::copyBuffer(connId.data(), connId.size())};
}

inline TransportParameter encodeStatelessResetToken(
    const StatelessResetToken& token) {
  TransportParameter statelessReset;
  statelessReset.parameter = TransportParameterId::stateless_reset_token;
  statelessReset.value = folly::IOBuf::copyBuffer(token.data(), token.size());
  return statelessReset;
}

struct QuicConnectionStateBase;

std::vector<TransportParameter> getSupportedExtTransportParams(
    const QuicConnectionStateBase& conn);

} // namespace quic
