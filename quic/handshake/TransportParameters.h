/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/record/Extensions.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/Types.h>

namespace quic {

enum class TransportParameterId : uint16_t {
  original_connection_id = 0x0000,
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
};

struct TransportParameter {
  TransportParameterId parameter;
  fizz::Buf value;

  TransportParameter() {}

  TransportParameter(TransportParameterId p, fizz::Buf v)
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
  explicit CustomTransportParameter(uint16_t id) : id_(id) {}

  uint16_t id_;
};

class CustomStringTransportParameter : public CustomTransportParameter {
 public:
  CustomStringTransportParameter(uint16_t id, std::string value);

  TransportParameter encode() const override;

 private:
  std::string value_;
};

class CustomBlobTransportParameter : public CustomTransportParameter {
 public:
  CustomBlobTransportParameter(uint16_t id, fizz::Buf value);

  TransportParameter encode() const override;

 private:
  fizz::Buf value_;
};

class CustomIntegralTransportParameter : public CustomTransportParameter {
 public:
  CustomIntegralTransportParameter(uint16_t id, uint64_t value);

  TransportParameter encode() const override;

 private:
  uint64_t value_;
};

struct ClientTransportParameters {
  folly::Optional<QuicVersion> initial_version;
  std::vector<TransportParameter> parameters;
};

struct ServerTransportParameters {
  folly::Optional<QuicVersion> negotiated_version;
  std::vector<QuicVersion> supported_versions;
  std::vector<TransportParameter> parameters;
};

struct TicketTransportParameters {
  folly::Optional<QuicVersion> negotiated_version;
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

inline TransportParameter encodeStatelessResetToken(
    const StatelessResetToken& token) {
  TransportParameter statelessReset;
  statelessReset.parameter = TransportParameterId::stateless_reset_token;
  statelessReset.value = folly::IOBuf::copyBuffer(token.data(), token.size());
  return statelessReset;
}

inline fizz::Extension encodeExtension(
    const quic::ClientTransportParameters& params) {
  fizz::Extension ext;
  ext.extension_type = fizz::ExtensionType::quic_transport_parameters;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 40);
  if (params.initial_version) {
    fizz::detail::write(params.initial_version.value(), appender);
  }
  fizz::detail::writeVector<uint16_t>(params.parameters, appender);
  return ext;
}

inline fizz::Extension encodeExtension(
    const quic::ServerTransportParameters& params) {
  fizz::Extension ext;
  ext.extension_type = fizz::ExtensionType::quic_transport_parameters;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 40);
  if (params.negotiated_version) {
    fizz::detail::write(params.negotiated_version.value(), appender);
    fizz::detail::writeVector<uint8_t>(params.supported_versions, appender);
  }
  fizz::detail::writeVector<uint16_t>(params.parameters, appender);
  return ext;
}

inline fizz::Extension encodeExtension(
    const quic::TicketTransportParameters& params) {
  fizz::Extension ext;
  ext.extension_type = fizz::ExtensionType::quic_transport_parameters;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 40);
  if (params.negotiated_version) {
    fizz::detail::write(params.negotiated_version.value(), appender);
  }
  fizz::detail::writeVector<uint16_t>(params.parameters, appender);
  return ext;
}

} // namespace quic

namespace fizz {

template <>
inline folly::Optional<quic::ClientTransportParameters> getExtension(
    const std::vector<Extension>& extensions) {
  auto it = findExtension(extensions, ExtensionType::quic_transport_parameters);
  if (it == extensions.end()) {
    return folly::none;
  }
  quic::ClientTransportParameters parameters;
  folly::io::Cursor cursor(it->extension_data.get());
  folly::io::Cursor versionCursor(it->extension_data.get());
  quic::QuicVersion tryVersion{quic::QuicVersion::MVFST_INVALID};
  if (cursor.canAdvance(sizeof(tryVersion))) {
    detail::read(tryVersion, versionCursor);
  }
  if (tryVersion == quic::QuicVersion::MVFST_OLD) {
    parameters.initial_version = tryVersion;
    cursor.skip(sizeof(tryVersion));
  }
  detail::readVector<uint16_t>(parameters.parameters, cursor);
  return std::move(parameters);
}

template <>
inline folly::Optional<quic::ServerTransportParameters> getExtension(
    const std::vector<Extension>& extensions) {
  auto it = findExtension(extensions, ExtensionType::quic_transport_parameters);
  if (it == extensions.end()) {
    return folly::none;
  }
  quic::ServerTransportParameters parameters;
  folly::io::Cursor cursor(it->extension_data.get());
  folly::io::Cursor versionCursor(it->extension_data.get());
  quic::QuicVersion tryVersion{quic::QuicVersion::MVFST_INVALID};
  if (cursor.canAdvance(sizeof(tryVersion))) {
    detail::read(tryVersion, versionCursor);
  }
  if (tryVersion == quic::QuicVersion::MVFST_OLD) {
    parameters.negotiated_version = tryVersion;
    cursor.skip(sizeof(tryVersion));
    detail::readVector<uint8_t>(parameters.supported_versions, cursor);
  }
  detail::readVector<uint16_t>(parameters.parameters, cursor);
  return std::move(parameters);
}

template <>
inline folly::Optional<quic::TicketTransportParameters> getExtension(
    const std::vector<Extension>& extensions) {
  auto it = findExtension(extensions, ExtensionType::quic_transport_parameters);
  if (it == extensions.end()) {
    return folly::none;
  }
  quic::TicketTransportParameters parameters;
  folly::io::Cursor cursor(it->extension_data.get());
  folly::io::Cursor versionCursor(it->extension_data.get());
  quic::QuicVersion tryVersion{quic::QuicVersion::MVFST_INVALID};
  if (versionCursor.canAdvance(sizeof(tryVersion))) {
    detail::read(tryVersion, versionCursor);
  }
  if (tryVersion == quic::QuicVersion::MVFST_OLD) {
    parameters.negotiated_version = tryVersion;
    cursor.skip(sizeof(tryVersion));
  }
  detail::readVector<uint16_t>(parameters.parameters, cursor);
  return std::move(parameters);
}

namespace detail {

template <>
struct Reader<quic::TransportParameter> {
  template <class T>
  size_t read(quic::TransportParameter& param, folly::io::Cursor& cursor) {
    size_t len = 0;
    len += detail::read(param.parameter, cursor);
    len += readBuf<uint16_t>(param.value, cursor);
    return len;
  }
};

template <>
struct Writer<quic::TransportParameter> {
  template <class T>
  void write(const quic::TransportParameter& param, folly::io::Appender& out) {
    detail::write(param.parameter, out);
    detail::writeBuf<uint16_t>(param.value, out);
  }
};

template <>
struct Sizer<quic::TransportParameter> {
  template <class T>
  size_t getSize(const quic::TransportParameter& param) {
    return sizeof(param.parameter) + getBufSize<uint16_t>(param.value);
  }
};
} // namespace detail
} // namespace fizz
