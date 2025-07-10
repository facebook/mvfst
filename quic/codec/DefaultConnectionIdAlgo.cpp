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
quic::Expected<void, quic::QuicError> setVersionBitsInConnId(
    quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (UNLIKELY(connId.size() == 0)) {
    return quic::make_unexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR,
        "ConnectionId is too small for version"));
  }
  // clear 0-1 bits
  connId.data()[0] &= (~kShortVersionBitsMask);
  connId.data()[0] |=
      (kShortVersionBitsMask & (static_cast<uint8_t>(version) << 6));
  return {};
}

/**
 * Extract the version id bits (0 - 1) from the given ConnectionId
 */
quic::Expected<quic::ConnectionIdVersion, quic::QuicError>
getVersionBitsFromConnId(const quic::ConnectionId& connId) noexcept {
  if (UNLIKELY(connId.size() == 0)) {
    return quic::make_unexpected(quic::QuicError(
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
quic::Expected<void, quic::QuicError> setHostIdBitsInConnId(
    quic::ConnectionId& connId,
    uint32_t hostId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return quic::make_unexpected(quic::QuicError(
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
    return {};
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V2"));
    }
    connId.data()[1] = hostId >> 16;
    connId.data()[2] = hostId >> 8;
    connId.data()[3] = hostId;
    return {};
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V3"));
    }
    connId.data()[1] = hostId >> 24;
    connId.data()[2] = hostId >> 16;
    connId.data()[3] = hostId >> 8;
    connId.data()[4] = hostId;
    return {};
  } else {
    return quic::make_unexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}

/**
 * Extract the host id bits from the given ConnectionId
 */
quic::Expected<uint32_t, quic::QuicError> getHostIdBitsInConnId(
    const quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
    return quic::make_unexpected(quic::QuicError(
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
      return quic::make_unexpected(quic::QuicError(
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
      return quic::make_unexpected(quic::QuicError(
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
    return quic::make_unexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}

/**
 * Sets the given 8-bit workerId into the given connectionId's
 */
quic::Expected<void, quic::QuicError> setWorkerIdBitsInConnId(
    quic::ConnectionId& connId,
    uint8_t workerId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return quic::make_unexpected(quic::QuicError(
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
    return {};
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V2"));
    }
    connId.data()[4] = workerId;
    return {};
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for hostid V3"));
    }
    connId.data()[5] = workerId;
    return {};
  } else {
    return quic::make_unexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}

/**
 * Extracts the 'workerId' bits from the given ConnectionId
 */
quic::Expected<uint8_t, quic::QuicError> getWorkerIdFromConnId(
    const quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return quic::make_unexpected(quic::QuicError(
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
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for workerid V2"));
    }
    return connId.data()[4];
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for workerid V3"));
    }
    return connId.data()[5];
  } else {
    return quic::make_unexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}

/**
 * Sets the server id bit into the given ConnectionId
 */
quic::Expected<void, quic::QuicError> setProcessIdBitsInConnId(
    quic::ConnectionId& connId,
    uint8_t processId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid"));
    }
    // clear the 26th bit
    connId.data()[3] &= (~kProcessIdV1BitMask);
    connId.data()[3] |= (kProcessIdV1BitMask & (processId << 5));
    return {};
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid V2"));
    }
    // clear the 40th bit
    connId.data()[5] &= (~kProcessIdV2BitMask);
    connId.data()[5] |= (kProcessIdV2BitMask & (processId << 7));
    return {};
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid V3"));
    }
    // clear the 40th bit
    connId.data()[6] &= (~kProcessIdV3BitMask);
    connId.data()[6] |= (kProcessIdV3BitMask & (processId << 7));
    return {};
  } else {
    return quic::make_unexpected(quic::QuicError(
        quic::TransportErrorCode::INTERNAL_ERROR, "Unsupported CID version"));
  }
}

/**
 * Extract the server id bit (at 26th bit) from the given ConnectionId
 */
quic::Expected<uint8_t, quic::QuicError> getProcessIdBitsFromConnId(
    const quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (connId.size() < quic::kMinSelfConnectionIdV1Size) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid"));
    }
    uint8_t processId = 0;
    processId = (kProcessIdV1BitMask & connId.data()[3]) >> 5;
    return processId;
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid V2"));
    }
    uint8_t processId = 0;
    processId = (kProcessIdV2BitMask & connId.data()[5]) >> 7;
    return processId;
  } else if (version == quic::ConnectionIdVersion::V3) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV3Size)) {
      return quic::make_unexpected(quic::QuicError(
          quic::TransportErrorCode::INTERNAL_ERROR,
          "ConnectionId is too small for processid V3"));
    }
    uint8_t processId = 0;
    processId = (kProcessIdV3BitMask & connId.data()[6]) >> 7;
    return processId;
  } else {
    return quic::make_unexpected(quic::QuicError(
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

quic::Expected<ServerConnectionIdParams, QuicError>
DefaultConnectionIdAlgo::parseConnectionIdDefault(
    const ConnectionId& id) noexcept {
  auto expectingVersion = getVersionBitsFromConnId(id);
  if (UNLIKELY(!expectingVersion)) {
    return quic::make_unexpected(expectingVersion.error());
  }
  auto expectingHost = getHostIdBitsInConnId(id, *expectingVersion);
  if (UNLIKELY(!expectingHost)) {
    return quic::make_unexpected(expectingHost.error());
  }
  auto expectingProcess = getProcessIdBitsFromConnId(id, *expectingVersion);
  if (UNLIKELY(!expectingProcess)) {
    return quic::make_unexpected(expectingProcess.error());
  }
  auto expectingWorker = getWorkerIdFromConnId(id, *expectingVersion);
  if (UNLIKELY(!expectingWorker)) {
    return quic::make_unexpected(expectingWorker.error());
  }
  ServerConnectionIdParams serverConnIdParams(
      *expectingVersion, *expectingHost, *expectingProcess, *expectingWorker);
  return serverConnIdParams;
}

quic::Expected<ServerConnectionIdParams, QuicError>
DefaultConnectionIdAlgo::parseConnectionId(const ConnectionId& id) noexcept {
  return parseConnectionIdDefault(id);
}

quic::Expected<ConnectionId, QuicError>
DefaultConnectionIdAlgo::encodeConnectionId(
    const ServerConnectionIdParams& params) noexcept {
  // Create a random connection id using createRandom
  auto connIdExpected = ConnectionId::createRandom(kDefaultConnectionIdSize);
  if (!connIdExpected) {
    return quic::make_unexpected(connIdExpected.error());
  }

  ConnectionId connId = std::move(*connIdExpected);

  auto versionResult = setVersionBitsInConnId(connId, params.version);
  if (UNLIKELY(!versionResult.has_value())) {
    return quic::make_unexpected(versionResult.error());
  }

  auto hostIdResult =
      setHostIdBitsInConnId(connId, params.hostId, params.version);
  if (UNLIKELY(!hostIdResult.has_value())) {
    return quic::make_unexpected(hostIdResult.error());
  }

  auto processIdResult =
      setProcessIdBitsInConnId(connId, params.processId, params.version);
  if (UNLIKELY(!processIdResult.has_value())) {
    return quic::make_unexpected(processIdResult.error());
  }

  auto workerIdResult =
      setWorkerIdBitsInConnId(connId, params.workerId, params.version);
  if (UNLIKELY(!workerIdResult.has_value())) {
    return quic::make_unexpected(workerIdResult.error());
  }
  return connId;
}

} // namespace quic
