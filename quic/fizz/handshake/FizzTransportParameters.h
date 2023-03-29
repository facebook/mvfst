/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/record/Extensions.h>
#include <quic/codec/QuicInteger.h>
#include <quic/common/BufUtil.h>
#include <quic/handshake/TransportParameters.h>

namespace quic {

inline fizz::ExtensionType getQuicTransportParametersExtention(
    QuicVersion version) {
  if (version == QuicVersion::QUIC_V1 ||
      version == QuicVersion::QUIC_V1_ALIAS) {
    return fizz::ExtensionType::quic_transport_parameters;
  } else {
    return fizz::ExtensionType::quic_transport_parameters_draft;
  }
}

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

inline void removeDuplicateParams(std::vector<TransportParameter>& params) {
  std::sort(
      params.begin(),
      params.end(),
      [](const TransportParameter& a, const TransportParameter& b) {
        return a.parameter < b.parameter;
      });
  params.erase(
      std::unique(
          params.begin(),
          params.end(),
          [](const TransportParameter& a, const TransportParameter& b) {
            return a.parameter == b.parameter;
          }),
      params.end());
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
  removeDuplicateParams(parameters);
}

// TODO all the 40s here in the appenders are very likely not the optimal
// values, we should replace with how many varints we actually write.
inline fizz::Extension encodeExtension(
    const quic::ClientTransportParameters& params,
    QuicVersion encodingVersion) {
  fizz::Extension ext;
  ext.extension_type = getQuicTransportParametersExtention(encodingVersion);
  ext.extension_data = folly::IOBuf::create(0);
  BufAppender appender(ext.extension_data.get(), 40);
  encodeVarintParams(params.parameters, appender);
  return ext;
}

inline fizz::Extension encodeExtension(
    const quic::ServerTransportParameters& params,
    QuicVersion encodingVersion) {
  fizz::Extension ext;
  ext.extension_type = getQuicTransportParametersExtention(encodingVersion);
  ext.extension_data = folly::IOBuf::create(0);
  BufAppender appender(ext.extension_data.get(), 40);
  encodeVarintParams(params.parameters, appender);
  return ext;
}

inline fizz::Extension encodeExtension(
    const quic::TicketTransportParameters& params,
    QuicVersion encodingVersion) {
  fizz::Extension ext;
  ext.extension_type = getQuicTransportParametersExtention(encodingVersion);
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
  auto extensionType = getQuicTransportParametersExtention(encodingVersion);
  auto it = findExtension(extensions, extensionType);
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
  auto extensionType = getQuicTransportParametersExtention(encodingVersion);
  auto it = findExtension(extensions, extensionType);
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
  auto extensionType = getQuicTransportParametersExtention(encodingVersion);
  auto it = findExtension(extensions, extensionType);
  if (it == extensions.end()) {
    return folly::none;
  }
  quic::TicketTransportParameters parameters;
  folly::io::Cursor cursor(it->extension_data.get());
  decodeVarintParams(parameters.parameters, cursor);
  return parameters;
}

// Performs any required validation checks on the given extensions
//
// Currently verifies that the QUIC transport params extension
// uses the correct extension number for the Quic version,
// and that the extension list does not have more than
// one QUIC transport params extension.
//
// Throws an error on an invalid list of extensions.
inline void validateTransportExtensions(
    const std::vector<Extension>& extensions,
    const quic::QuicVersion encodingVersion) {
  auto found = false;
  for (const auto& extension : extensions) {
    if (extension.extension_type ==
            fizz::ExtensionType::quic_transport_parameters ||
        extension.extension_type ==
            fizz::ExtensionType::quic_transport_parameters_draft) {
      if (found) {
        // This is a duplicate.
        throw fizz::FizzException(
            "duplicate quic transport parameters extension",
            fizz::AlertDescription::illegal_parameter);
      } else if (
          (encodingVersion == quic::QuicVersion::QUIC_V1 ||
           encodingVersion == quic::QuicVersion::QUIC_V1_ALIAS) &&
          extension.extension_type !=
              fizz::ExtensionType::quic_transport_parameters) {
        // This is QUIC v1 using an incorrect transport parameters extension
        // type
        throw fizz::FizzException(
            fmt::format(
                "unexpected extension type ({:#x}) for quic v1",
                extension.extension_type),
            fizz::AlertDescription::illegal_parameter);
      } else if (
          encodingVersion == quic::QuicVersion::QUIC_DRAFT &&
          extension.extension_type !=
              fizz::ExtensionType::quic_transport_parameters_draft) {
        // This is a QUIC draft version using an incorrect transport parameters
        // extension type
        throw fizz::FizzException(
            fmt::format(
                "unexpected extension type ({:#x}) for quic draft version",
                extension.extension_type),
            fizz::AlertDescription::illegal_parameter);
      }
      found = true;
    }
  }
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
