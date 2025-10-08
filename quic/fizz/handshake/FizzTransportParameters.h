/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/record/Extensions.h>
#include <quic/common/BufUtil.h>
#include <quic/folly_utils/Utils.h>
#include <quic/handshake/TransportParameters.h>

namespace {

inline quic::BufPtr encodeVarintParams(
    const std::vector<quic::TransportParameter>& parameters) {
  // chain all encodings
  quic::BufQueue queue;
  for (const auto& param : parameters) {
    queue.append(param.encode());
  }

  if (auto encodedParams = queue.move()) {
    // coalesce and return
    encodedParams->coalesce();
    return encodedParams;
  }

  // callers expect empty buf if no parameters supplied
  return quic::BufHelpers::create(0);
}

inline fizz::ExtensionType getQuicTransportParametersExtention(
    quic::QuicVersion version) {
  if (version == quic::QuicVersion::QUIC_V1 ||
      version == quic::QuicVersion::QUIC_V1_ALIAS ||
      version == quic::QuicVersion::QUIC_V1_ALIAS2 ||
      version == quic::QuicVersion::MVFST_PRIMING) {
    return fizz::ExtensionType::quic_transport_parameters;
  } else {
    return fizz::ExtensionType::quic_transport_parameters_draft;
  }
}

} // namespace

namespace quic {

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
    ContiguousReadCursor& cursor) {
  while (!cursor.isAtEnd()) {
    auto id = quic::decodeQuicInteger(cursor);
    if (!id) {
      throw std::runtime_error("Could not parse transport parameter id.");
    }
    auto len = quic::decodeQuicInteger(cursor);
    if (!len) {
      throw std::runtime_error("Could not parse transport parameter length.");
    }
    if (cursor.remaining() < len.value().first) {
      throw std::runtime_error("Not enough bytes to read transport parameter");
    }
    BufPtr val = BufHelpers::create(len.value().first);
    CHECK(cursor.tryPull(val->writableData(), len.value().first));
    val->append(len.value().first);
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
  ext.extension_data = encodeVarintParams(params.parameters);
  return ext;
}

inline fizz::Extension encodeExtension(
    const quic::ServerTransportParameters& params,
    QuicVersion encodingVersion) {
  fizz::Extension ext;
  ext.extension_type = getQuicTransportParametersExtention(encodingVersion);
  ext.extension_data = encodeVarintParams(params.parameters);
  return ext;
}

inline fizz::Extension encodeExtension(
    const quic::TicketTransportParameters& params,
    QuicVersion encodingVersion) {
  fizz::Extension ext;
  ext.extension_type = getQuicTransportParametersExtention(encodingVersion);
  ext.extension_data = encodeVarintParams(params.parameters);
  return ext;
}

} // namespace quic

namespace fizz {

inline quic::Optional<quic::ClientTransportParameters> getClientExtension(
    const std::vector<Extension>& extensions,
    quic::QuicVersion encodingVersion) {
  auto extensionType = getQuicTransportParametersExtention(encodingVersion);
  auto it = findExtension(extensions, extensionType);
  if (it == extensions.end()) {
    return std::nullopt;
  }
  quic::ClientTransportParameters parameters;
  auto extensionCoalesced = it->extension_data->coalesce();
  quic::ContiguousReadCursor cursor(
      extensionCoalesced.data(), extensionCoalesced.size());
  decodeVarintParams(parameters.parameters, cursor);
  return parameters;
}

inline quic::Optional<quic::ServerTransportParameters> getServerExtension(
    const std::vector<Extension>& extensions,
    quic::QuicVersion encodingVersion) {
  auto extensionType = getQuicTransportParametersExtention(encodingVersion);
  auto it = findExtension(extensions, extensionType);
  if (it == extensions.end()) {
    return std::nullopt;
  }
  quic::ServerTransportParameters parameters;
  auto extensionCoalesced = it->extension_data->coalesce();
  quic::ContiguousReadCursor cursor(
      extensionCoalesced.data(), extensionCoalesced.size());
  decodeVarintParams(parameters.parameters, cursor);
  return parameters;
}

inline quic::Optional<quic::TicketTransportParameters> getTicketExtension(
    const std::vector<Extension>& extensions,
    quic::QuicVersion encodingVersion) {
  auto extensionType = getQuicTransportParametersExtention(encodingVersion);
  auto it = findExtension(extensions, extensionType);
  if (it == extensions.end()) {
    return std::nullopt;
  }
  quic::TicketTransportParameters parameters;
  auto extensionCoalesced = it->extension_data->coalesce();
  quic::ContiguousReadCursor cursor(
      extensionCoalesced.data(), extensionCoalesced.size());
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
           encodingVersion == quic::QuicVersion::QUIC_V1_ALIAS ||
           encodingVersion == quic::QuicVersion::QUIC_V1_ALIAS2 ||
           encodingVersion == quic::QuicVersion::MVFST_PRIMING) &&
          extension.extension_type !=
              fizz::ExtensionType::quic_transport_parameters) {
        // This is QUIC v1 using an incorrect transport parameters extension
        // type
        throw fizz::FizzException(
            fmt::format(
                "unexpected extension type ({:#x}) for quic v1",
                folly::to_underlying(extension.extension_type)),
            fizz::AlertDescription::illegal_parameter);
      }
      found = true;
    }
  }
}
} // namespace fizz
