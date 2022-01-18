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
  min_ack_delay = 0xff02de1a,
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
};

class CustomTransportParameter {
 public:
  TransportParameterId getParameterId();

  virtual TransportParameter encode() const = 0;

  virtual ~CustomTransportParameter() = default;

 protected:
  explicit CustomTransportParameter(uint64_t id) : id_(id) {}

  uint64_t id_;
};

class CustomStringTransportParameter : public CustomTransportParameter {
 public:
  CustomStringTransportParameter(uint64_t id, std::string value);

  TransportParameter encode() const override;

 private:
  std::string value_;
};

class CustomBlobTransportParameter : public CustomTransportParameter {
 public:
  CustomBlobTransportParameter(
      uint64_t id,
      std::unique_ptr<folly::IOBuf> value);

  TransportParameter encode() const override;

 private:
  std::unique_ptr<folly::IOBuf> value_;
};

class CustomIntegralTransportParameter : public CustomTransportParameter {
 public:
  CustomIntegralTransportParameter(uint64_t id, uint64_t value);

  TransportParameter encode() const override;

 private:
  uint64_t value_;
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

folly::Optional<uint64_t> getIntegerParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters);

folly::Optional<ConnectionId> getConnIdParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters);

folly::Optional<StatelessResetToken> getStatelessResetTokenParameter(
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
} // namespace quic
