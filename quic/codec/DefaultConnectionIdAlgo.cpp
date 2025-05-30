/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/DefaultConnectionIdAlgo.h>

#include <folly/Random.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/QuicConnectionId.h>

namespace {
// mask to extract process id bit from the connectionId
constexpr uint8_t kProcessIdV1BitMask = 0x20;
constexpr uint8_t kProcessIdV2BitMask = 0x80;
constexpr uint8_t kProcessIdV3BitMask = 0x80;
// mask to set the first 6 bits from host-id
constexpr uint8_t kHostIdV1FirstByteMask = 0x3f;
// mask to set the next 8 bits from host-id
constexpr uint8_t kHostIdV1SecondByteMask = 0xff;
// mask to set the last 2 bits from host-id
constexpr uint8_t kHostIdV1ThirdByteMask = 0xc0;
// mask to set the first 6 bits from worker-id
constexpr uint8_t kWorkerIdV1FirstByteMask = 0xfc;
// mask to set the last 2 bits from host-id
constexpr uint8_t kWorkerIdV1SecondByteMask = 0x03;
// first 2 bits in the connection id is reserved for versioning of the conn id
constexpr uint8_t kShortVersionBitsMask = 0xc0;

/**
 * Sets the short version id bits (0 - 1) into the given ConnectionId
 */
folly::Expected<folly::Unit, quic::QuicError> setVersionBitsInConnId(
    quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (UNLIKELY(connId.size() == 0)) {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR,
        "ConnectionId is too small for version"));
  }
  // clear 0-1 bits
  connId.data()[0] &= (~kShortVersionBitsMask);
  connId.data()[0] |=
      (kShortVersionBitsMask & (static_cast<uint8_t>(version) << 6));
  return folly::unit;
}

/**
 * Extract the version id bits (0 - 1) from the given ConnectionId
 */
folly::Expected<quic::ConnectionIdVersion, quic::QuicError>
getVersionBitsFromConnId(const quic::ConnectionId& connId) noexcept {
  if (UNLIKELY(connId.size() == 0)) {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR,
        "ConnectionId is too small for version"));
  }
  uint8_t version = 0;
  version = (kShortVersionBitsMask & connId.data()[0]) >> 6;
  return static_cast<quic::ConnectionIdVersion>(version);
}

/**
 * Sets the host id bits into the given ConnectionId
 */
folly::Expected<folly::Unit, quic::QuicError> setHostIdBitsInConnId(
    quic::ConnectionId& connId,
    uint32_t hostId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V1"));
    }
    uint16_t hostIdV1 = hostId;
    // clear 2 - 7 bits
    connId.data()[0] &= ~kHostIdV1FirstByteMask;
    // clear 8 - 15 bits
    connId.data()[1] &= ~kHostIdV1SecondByteMask;
    // clear 16 - 17 bits
    connId.data()[2] &= ~kHostIdV1ThirdByteMask;

    // set 2 - 7 bits in the connId with the first 6 bits of the worker id
    connId.data()[0] |= (kHostIdV1FirstByteMask & (hostIdV1 >> 10));
    // set 8 - 15 bits in the connId with the next 8 bits of the worker id
    connId.data()[1] |= (kHostIdV1SecondByteMask & (hostIdV1 >> 2));
    // set 16 - 17 bits in the connId with the last 2 bits of the worker id
    connId.data()[2] |= (kHostIdV1ThirdByteMask & (hostIdV1 << 6));
    return folly::unit;
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V2"));
    }
    connId.data()[1] = hostId >> 16;
    connId.data()[2] = hostId >> 8;
    connId.data()[3] = hostId;
    return folly::unit;
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V3"));
    }
    connId.data()[1] = hostId >> 24;
    connId.data()[2] = hostId >> 16;
    connId.data()[3] = hostId >> 8;
    connId.data()[4] = hostId;
    return folly::unit;
  } else {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}

/**
 * Extract the host id bits from the given ConnectionId
 */
folly::Expected<uint32_t, quic::QuicError> getHostIdBitsInConnId(
    const quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR,
        "ConnectionId is too small for hostid"));
  }
  if (version == quic::ConnectionIdVersion::V1) {
    uint16_t hostId = 0;
    // get 2 - 7 bits from the connId and set first 6 bits of the host id
    hostId = (kHostIdV1FirstByteMask & (connId.data()[0]));
    // shift by 10 bits and make room for the last 10 bits
    hostId = hostId << 10;
    // get 8 - 15 bits from the connId
    hostId |= (kHostIdV1SecondByteMask & connId.data()[1]) << 2;
    // get 16 - 17 bits from the connId
    hostId |= (kHostIdV1ThirdByteMask & connId.data()[2]) >> 6;
    return hostId;
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V2"));
    }
    uint32_t hostId = 0;
    hostId |= connId.data()[1] << 16;
    hostId |= connId.data()[2] << 8;
    hostId |= connId.data()[3];
    return hostId;
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V3"));
    }
    uint32_t hostId = 0;
    hostId |= connId.data()[1] << 24;
    hostId |= connId.data()[2] << 16;
    hostId |= connId.data()[3] << 8;
    hostId |= connId.data()[4];
    return hostId;
  } else {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}

/**
 * Sets the given 8-bit workerId into the given connectionId's
 */
folly::Expected<folly::Unit, quic::QuicError> setWorkerIdBitsInConnId(
    quic::ConnectionId& connId,
    uint8_t workerId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for workerid"));
    }
    // clear 18-23 bits
    connId.data()[2] &= 0xc0;
    // clear 24-25 bits
    connId.data()[3] &= 0x3f;
    // set 18 - 23 bits in the connId with first 6 bits of the worker id
    connId.data()[2] |= (kWorkerIdV1FirstByteMask & workerId) >> 2;
    // set 24 - 25 bits in the connId with the last 2 bits of the worker id
    connId.data()[3] |= (kWorkerIdV1SecondByteMask & workerId) << 6;
    return folly::unit;
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V2"));
    }
    connId.data()[4] = workerId;
    return folly::unit;
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V3"));
    }
    connId.data()[5] = workerId;
    return folly::unit;
  } else {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}

/**
 * Extracts the 'workerId' bits from the given ConnectionId
 */
folly::Expected<uint8_t, quic::QuicError> getWorkerIdFromConnId(
    const quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for workerid"));
    }
    // get 18 - 23 bits from the connId
    uint8_t workerId = connId.data()[2] << 2;
    // get 24 - 25 bits in the connId
    workerId |= connId.data()[3] >> 6;
    return workerId;
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for workerid V2"));
    }
    return connId.data()[4];
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for workerid V3"));
    }
    return connId.data()[5];
  } else {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}

/**
 * Sets the server id bit into the given ConnectionId
 */
folly::Expected<folly::Unit, quic::QuicError> setProcessIdBitsInConnId(
    quic::ConnectionId& connId,
    uint8_t processId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid"));
    }
    // clear the 26th bit
    connId.data()[3] &= (~kProcessIdV1BitMask);
    connId.data()[3] |= (kProcessIdV1BitMask & (processId << 5));
    return folly::unit;
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid V2"));
    }
    // clear the 40th bit
    connId.data()[5] &= (~kProcessIdV2BitMask);
    connId.data()[5] |= (kProcessIdV2BitMask & (processId << 7));
    return folly::unit;
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid V3"));
    }
    // clear the 40th bit
    connId.data()[6] &= (~kProcessIdV3BitMask);
    connId.data()[6] |= (kProcessIdV3BitMask & (processId << 7));
    return folly::unit;
  } else {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}

/**
 * Extract the server id bit (at 26th bit) from the given ConnectionId
 */
folly::Expected<uint8_t, quic::QuicError> getProcessIdBitsFromConnId(
    const quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (connId.size() < quic::kMinSelfConnectionIdV1Size) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid"));
    }
    uint8_t processId = 0;
    processId = (kProcessIdV1BitMask & connId.data()[3]) >> 5;
    return processId;
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid V2"));
    }
    uint8_t processId = 0;
    processId = (kProcessIdV2BitMask & connId.data()[5]) >> 7;
    return processId;
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return folly::makeUnexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid V3"));
    }
    uint8_t processId = 0;
    processId = (kProcessIdV3BitMask & connId.data()[6]) >> 7;
    return processId;
  } else {
    return folly::makeUnexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}
} // namespace

namespace quic {

bool DefaultConnectionIdAlgo::canParse(const ConnectionId& id) const noexcept {
  auto versionExpected = getVersionBitsFromConnId(id);
  if (!versionExpected) {
    return false;
  }
  auto version = *versionExpected;
  if (version == ConnectionIdVersion::V1) {
    return (id.size() >= kMinSelfConnectionIdV1Size);
  } else if (version == ConnectionIdVersion::V2) {
    return (id.size() >= kMinSelfConnectionIdV2Size);
  } else if (version == ConnectionIdVersion::V3) {
    return (id.size() >= kMinSelfConnectionIdV3Size);
  } else {
    return false;
  }
}

folly::Expected<ServerConnectionIdParams, QuicError>
DefaultConnectionIdAlgo::parseConnectionIdDefault(
    const ConnectionId& id) noexcept {
  auto expectingVersion = getVersionBitsFromConnId(id);
  if (UNLIKELY(!expectingVersion)) {
    return folly::makeUnexpected(expectingVersion.error());
  }
  auto expectingHost = getHostIdBitsInConnId(id, *expectingVersion);
  if (UNLIKELY(!expectingHost)) {
    return folly::makeUnexpected(expectingHost.error());
  }
  auto expectingProcess = getProcessIdBitsFromConnId(id, *expectingVersion);
  if (UNLIKELY(!expectingProcess)) {
    return folly::makeUnexpected(expectingProcess.error());
  }
  auto expectingWorker = getWorkerIdFromConnId(id, *expectingVersion);
  if (UNLIKELY(!expectingWorker)) {
    return folly::makeUnexpected(expectingWorker.error());
  }
  ServerConnectionIdParams serverConnIdParams(
      *expectingVersion, *expectingHost, *expectingProcess, *expectingWorker);
  return serverConnIdParams;
}

folly::Expected<ServerConnectionIdParams, QuicError>
DefaultConnectionIdAlgo::parseConnectionId(const ConnectionId& id) noexcept {
  return parseConnectionIdDefault(id);
}

folly::Expected<ConnectionId, QuicError>
DefaultConnectionIdAlgo::encodeConnectionId(
    const ServerConnectionIdParams& params) noexcept {
  // Create a random connection id using createRandom
  auto connIdExpected = ConnectionId::createRandom(kDefaultConnectionIdSize);
  if (!connIdExpected) {
    return folly::makeUnexpected(connIdExpected.error());
  }

  ConnectionId connId = std::move(*connIdExpected);
  auto expected =
      setVersionBitsInConnId(connId, params.version)
          .then([&](auto) {
            return setHostIdBitsInConnId(connId, params.hostId, params.version);
          })
          .then([&](auto) {
            return setProcessIdBitsInConnId(
                connId, params.processId, params.version);
          })
          .then([&](auto) {
            return setWorkerIdBitsInConnId(
                connId, params.workerId, params.version);
          });
  if (UNLIKELY(expected.hasError())) {
    // Convert QuicInternalException to QuicError
    return folly::makeUnexpected(QuicError(
        TransportErrorCode::INTERNAL_ERROR, "Failed to encode connection ID"));
  }
  return connId;
}

} // namespace quic
