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
folly::Expected<folly::Unit, quic::QuicInternalException>
setVersionBitsInConnId(
    quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
    return folly::makeUnexpected(quic::QuicInternalException(
        "ConnectionId is too small for version",
        quic::LocalErrorCode::INTERNAL_ERROR));
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
folly::Expected<quic::ConnectionIdVersion, quic::QuicInternalException>
getVersionBitsFromConnId(const quic::ConnectionId& connId) noexcept {
  if (UNLIKELY(connId.size() == 0)) {
    return folly::makeUnexpected(quic::QuicInternalException(
        "ConnectionId is too small for version",
        quic::LocalErrorCode::INTERNAL_ERROR));
  }
  uint8_t version = 0;
  version = (kShortVersionBitsMask & connId.data()[0]) >> 6;
  return static_cast<quic::ConnectionIdVersion>(version);
}

/**
 * Sets the host id bits into the given ConnectionId
 */
folly::Expected<folly::Unit, quic::QuicInternalException> setHostIdBitsInConnId(
    quic::ConnectionId& connId,
    uint32_t hostId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for hostid V1",
          quic::LocalErrorCode::INTERNAL_ERROR));
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
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for hostid V2",
          quic::LocalErrorCode::INTERNAL_ERROR));
    }
    connId.data()[1] = hostId >> 16;
    connId.data()[2] = hostId >> 8;
    connId.data()[3] = hostId;
    return folly::unit;
  } else {
    return folly::makeUnexpected(quic::QuicInternalException(
        "Unsupported CID version", quic::LocalErrorCode::INTERNAL_ERROR));
  }
}

/**
 * Extract the host id bits from the given ConnectionId
 */
folly::Expected<uint32_t, quic::QuicInternalException> getHostIdBitsInConnId(
    const quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
    return folly::makeUnexpected(quic::QuicInternalException(
        "ConnectionId is too small for hostid",
        quic::LocalErrorCode::INTERNAL_ERROR));
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
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for hostid V2",
          quic::LocalErrorCode::INTERNAL_ERROR));
    }
    uint32_t hostId = 0;
    hostId |= connId.data()[1] << 16;
    hostId |= connId.data()[2] << 8;
    hostId |= connId.data()[3];
    return hostId;
  } else {
    return folly::makeUnexpected(quic::QuicInternalException(
        "Unsupported CID version", quic::LocalErrorCode::INTERNAL_ERROR));
  }
}

/**
 * Sets the given 8-bit workerId into the given connectionId's
 */
folly::Expected<folly::Unit, quic::QuicInternalException>
setWorkerIdBitsInConnId(
    quic::ConnectionId& connId,
    uint8_t workerId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for workerid",
          quic::LocalErrorCode::INTERNAL_ERROR));
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
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for hostid V2",
          quic::LocalErrorCode::INTERNAL_ERROR));
    }
    connId.data()[4] = workerId;
    return folly::unit;
  } else {
    return folly::makeUnexpected(quic::QuicInternalException(
        "Unsupported CID version", quic::LocalErrorCode::INTERNAL_ERROR));
  }
}

/**
 * Extracts the 'workerId' bits from the given ConnectionId
 */
folly::Expected<uint8_t, quic::QuicInternalException> getWorkerIdFromConnId(
    const quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for workerid",
          quic::LocalErrorCode::INTERNAL_ERROR));
    }
    // get 18 - 23 bits from the connId
    uint8_t workerId = connId.data()[2] << 2;
    // get 24 - 25 bits in the connId
    workerId |= connId.data()[3] >> 6;
    return workerId;
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for workerid V2",
          quic::LocalErrorCode::INTERNAL_ERROR));
    }
    return connId.data()[4];
  } else {
    return folly::makeUnexpected(quic::QuicInternalException(
        "Unsupported CID version", quic::LocalErrorCode::INTERNAL_ERROR));
  }
}

/**
 * Sets the server id bit into the given ConnectionId
 */
folly::Expected<folly::Unit, quic::QuicInternalException>
setProcessIdBitsInConnId(
    quic::ConnectionId& connId,
    uint8_t processId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV1Size)) {
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for processid",
          quic::LocalErrorCode::INTERNAL_ERROR));
    }
    // clear the 26th bit
    connId.data()[3] &= (~kProcessIdV1BitMask);
    connId.data()[3] |= (kProcessIdV1BitMask & (processId << 5));
    return folly::unit;
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for processid V2",
          quic::LocalErrorCode::INTERNAL_ERROR));
    }
    // clear the 40th bit
    connId.data()[5] &= (~kProcessIdV2BitMask);
    connId.data()[5] |= (kProcessIdV2BitMask & (processId << 7));
    return folly::unit;
  } else {
    return folly::makeUnexpected(quic::QuicInternalException(
        "Unsupported CID version", quic::LocalErrorCode::INTERNAL_ERROR));
  }
}

/**
 * Extract the server id bit (at 26th bit) from the given ConnectionId
 */
folly::Expected<uint8_t, quic::QuicInternalException>
getProcessIdBitsFromConnId(
    const quic::ConnectionId& connId,
    quic::ConnectionIdVersion version) noexcept {
  if (version == quic::ConnectionIdVersion::V1) {
    if (connId.size() < quic::kMinSelfConnectionIdV1Size) {
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for processid",
          quic::LocalErrorCode::INTERNAL_ERROR));
    }
    uint8_t processId = 0;
    processId = (kProcessIdV1BitMask & connId.data()[3]) >> 5;
    return processId;
  } else if (version == quic::ConnectionIdVersion::V2) {
    if (UNLIKELY(connId.size() < quic::kMinSelfConnectionIdV2Size)) {
      return folly::makeUnexpected(quic::QuicInternalException(
          "ConnectionId is too small for processid V2",
          quic::LocalErrorCode::INTERNAL_ERROR));
    }
    uint8_t processId = 0;
    processId = (kProcessIdV2BitMask & connId.data()[5]) >> 7;
    return processId;
  } else {
    return folly::makeUnexpected(quic::QuicInternalException(
        "Unsupported CID version", quic::LocalErrorCode::INTERNAL_ERROR));
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
  } else {
    return false;
  }
}

folly::Expected<ServerConnectionIdParams, QuicInternalException>
DefaultConnectionIdAlgo::parseConnectionId(const ConnectionId& id) noexcept {
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

folly::Expected<ConnectionId, QuicInternalException>
DefaultConnectionIdAlgo::encodeConnectionId(
    const ServerConnectionIdParams& params) noexcept {
  // In case there is no client cid, create a random connection id.
  std::vector<uint8_t> connIdData(kDefaultConnectionIdSize);
  folly::Random::secureRandom(connIdData.data(), connIdData.size());
  ConnectionId connId = ConnectionId(std::move(connIdData));
  auto expected =
      setVersionBitsInConnId(connId, params.version)
          .then([&](auto) {
            setHostIdBitsInConnId(connId, params.hostId, params.version);
          })
          .then([&](auto) {
            setProcessIdBitsInConnId(connId, params.processId, params.version);
          })
          .then([&](auto) {
            setWorkerIdBitsInConnId(connId, params.workerId, params.version);
          });
  if (UNLIKELY(expected.hasError())) {
    return folly::makeUnexpected(expected.error());
  }
  return connId;
}

} // namespace quic
