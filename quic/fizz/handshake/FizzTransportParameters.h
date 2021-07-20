/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/record/Extensions.h>
#include <quic/codec/QuicInteger.h>
#include <quic/common/BufUtil.h>
#include <quic/handshake/TransportParameters.h>

namespace quic {

inline void encodeVarintParams(
    const std::vector<TransportParameter>& parameters,
    BufAppender& appender) {
  auto appenderOp = [&](auto val) { appender.writeBE(val); };
  for (auto& param : parameters) {
    encodeQuicInteger(static_cast<uint64_t>(param.parameter), appenderOp);
    size_t len = param.value->computeChainDataLength();
    encodeQuicInteger(len, appenderOp);
    appender.insert(param.value->clone());
  }
}

inline void decodeVarintParams(
    std::vector<TransportParameter>& parameters,
    folly::io::Cursor& cursor) {
  while (!cursor.isAtEnd()) {
    auto id = decodeQuicInteger(cursor);
    if (!id) {
      throw std::runtime_error("Could not parse transport parameter id.");
    }
    auto len = decodeQuicInteger(cursor);
    if (!len) {
      throw std::runtime_error("Could not parse transport parameter length.");
    }
    Buf val;
    cursor.clone(val, len.value().first);
    parameters.emplace_back(
        static_cast<TransportParameterId>(id.value().first), std::move(val));
  }
}

// TODO all the 40s here in the appenders are very likely not the optimal
// values, we should replace with how many varints we actually write.
inline fizz::Extension encodeExtension(
    const quic::ClientTransportParameters& params,
    QuicVersion encodingVersion) {
  // Silence the unused variable warning . It will be used for Quic V1.
  (void)encodingVersion;
  fizz::Extension ext;
  ext.extension_type = fizz::ExtensionType::quic_transport_parameters;
  ext.extension_data = folly::IOBuf::create(0);
  BufAppender appender(ext.extension_data.get(), 40);
  encodeVarintParams(params.parameters, appender);
  return ext;
}

inline fizz::Extension encodeExtension(
    const quic::ServerTransportParameters& params,
    QuicVersion encodingVersion) {
  // Silence the unused variable warning . It will be used for Quic V1.
  (void)encodingVersion;
  fizz::Extension ext;
  ext.extension_type = fizz::ExtensionType::quic_transport_parameters;
  ext.extension_data = folly::IOBuf::create(0);
  BufAppender appender(ext.extension_data.get(), 40);
  encodeVarintParams(params.parameters, appender);
  return ext;
}

inline fizz::Extension encodeExtension(
    const quic::TicketTransportParameters& params,
    QuicVersion encodingVersion) {
  // Silence the unused variable warning . It will be used for Quic V1.
  (void)encodingVersion;
  fizz::Extension ext;
  ext.extension_type = fizz::ExtensionType::quic_transport_parameters;
  ext.extension_data = folly::IOBuf::create(0);
  BufAppender appender(ext.extension_data.get(), 40);
  encodeVarintParams(params.parameters, appender);
  return ext;
}

} // namespace quic

namespace fizz {

inline folly::Optional<quic::ClientTransportParameters> getClientExtension(
    const std::vector<Extension>& extensions,
    quic::QuicVersion encodingVersion) {
  // Silence the unused variable warning . It will be used for Quic V1.
  (void)encodingVersion;
  auto it = findExtension(extensions, ExtensionType::quic_transport_parameters);
  if (it == extensions.end()) {
    return folly::none;
  }
  quic::ClientTransportParameters parameters;
  folly::io::Cursor cursor(it->extension_data.get());
  decodeVarintParams(parameters.parameters, cursor);
  return parameters;
}

inline folly::Optional<quic::ServerTransportParameters> getServerExtension(
    const std::vector<Extension>& extensions,
    quic::QuicVersion encodingVersion) {
  // Silence the unused variable warning . It will be used for Quic V1.
  (void)encodingVersion;
  auto it = findExtension(extensions, ExtensionType::quic_transport_parameters);
  if (it == extensions.end()) {
    return folly::none;
  }
  quic::ServerTransportParameters parameters;
  folly::io::Cursor cursor(it->extension_data.get());
  decodeVarintParams(parameters.parameters, cursor);
  return parameters;
}

inline folly::Optional<quic::TicketTransportParameters> getTicketExtension(
    const std::vector<Extension>& extensions,
    quic::QuicVersion encodingVersion) {
  // Silence the unused variable warning . It will be used for Quic V1.
  (void)encodingVersion;
  auto it = findExtension(extensions, ExtensionType::quic_transport_parameters);
  if (it == extensions.end()) {
    return folly::none;
  }
  quic::TicketTransportParameters parameters;
  folly::io::Cursor cursor(it->extension_data.get());
  decodeVarintParams(parameters.parameters, cursor);
  return parameters;
}

namespace detail {

template <>
struct Reader<quic::TransportParameter> {
  template <class T>
  size_t read(quic::TransportParameter& param, folly::io::Cursor& cursor) {
    size_t len = 0;
    uint16_t tmpId;
    len += detail::read(tmpId, cursor);
    param.parameter = static_cast<quic::TransportParameterId>(tmpId);
    len += readBuf<uint16_t>(param.value, cursor);
    return len;
  }
};

template <>
struct Writer<quic::TransportParameter> {
  template <class T>
  void write(const quic::TransportParameter& param, folly::io::Appender& out) {
    uint16_t tmpId = static_cast<uint16_t>(param.parameter);
    detail::write(tmpId, out);
    detail::writeBuf<uint16_t>(param.value, out);
  }
};

template <>
struct Sizer<quic::TransportParameter> {
  template <class T>
  size_t getSize(const quic::TransportParameter& param) {
    return sizeof(uint16_t) + getBufSize<uint16_t>(param.value);
  }
};
} // namespace detail
} // namespace fizz
