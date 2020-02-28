/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/record/Extensions.h>
#include <quic/handshake/TransportParameters.h>

namespace quic {

inline fizz::Extension encodeExtension(
    const quic::ClientTransportParameters& params) {
  fizz::Extension ext;
  ext.extension_type = fizz::ExtensionType::quic_transport_parameters;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 40);
  fizz::detail::writeVector<uint16_t>(params.parameters, appender);
  return ext;
}

inline fizz::Extension encodeExtension(
    const quic::ServerTransportParameters& params) {
  fizz::Extension ext;
  ext.extension_type = fizz::ExtensionType::quic_transport_parameters;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 40);
  fizz::detail::writeVector<uint16_t>(params.parameters, appender);
  return ext;
}

inline fizz::Extension encodeExtension(
    const quic::TicketTransportParameters& params) {
  fizz::Extension ext;
  ext.extension_type = fizz::ExtensionType::quic_transport_parameters;
  ext.extension_data = folly::IOBuf::create(0);
  folly::io::Appender appender(ext.extension_data.get(), 40);
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
  detail::readVector<uint16_t>(parameters.parameters, cursor);
  return parameters;
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
  detail::readVector<uint16_t>(parameters.parameters, cursor);
  return parameters;
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
  detail::readVector<uint16_t>(parameters.parameters, cursor);
  return parameters;
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
