/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/codec/DefaultConnectionIdAlgo.h>
#include <folly/Random.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>

namespace {
// mask to extract process id bit from the connectionId
constexpr uint8_t kProcessIdBitMask = 0x20;
// mask to set the first 6 bits from host-id
constexpr uint8_t kHostIdFirstByteMask = 0x3f;
// mask to set the next 8 bits from host-id
constexpr uint8_t kHostIdSecondByteMask = 0xff;
// mask to set the last 2 bits from host-id
constexpr uint8_t kHostIdThirdByteMask = 0xc0;
// mask to set the first 6 bits from worker-id
constexpr uint8_t kWorkerIdFirstByteMask = 0xfc;
// mask to set the last 2 bits from host-id
constexpr uint8_t kWorkerIdSecondByteMask = 0x03;
// first 2 bits in the connection id is reserved for versioning of the conn id
constexpr uint8_t kShortVersionBitsMask = 0xc0;

/**
 * Sets the short version id bits (0 - 1) into the given ConnectionId
 */
void setVersionBitsInConnId(quic::ConnectionId& connId, uint8_t version) {
  if (connId.size() < quic::kMinConnectionIdSize) {
    throw quic::QuicInternalException(
        "ConnectionId is too small for version",
        quic::LocalErrorCode::INTERNAL_ERROR);
  }
  // clear 0-1 bits
  connId.data()[0] &= (~kShortVersionBitsMask);
  connId.data()[0] |= (kShortVersionBitsMask & (version << 6));
}

/**
 * Extract the version id bits (0 - 1) from the given ConnectionId
 */
uint8_t getVersionBitsFromConnId(const quic::ConnectionId& connId) {
  if (connId.size() < quic::kMinConnectionIdSize) {
    throw quic::QuicInternalException(
        "ConnectionId is too small for version",
        quic::LocalErrorCode::INTERNAL_ERROR);
  }
  uint8_t version = 0;
  version = (kShortVersionBitsMask & connId.data()[0]) >> 6;
  return version;
}

/**
 * Sets the host id bits [2 - 17] bits into the given ConnectionId
 */
void setHostIdBitsInConnId(quic::ConnectionId& connId, uint16_t hostId) {
  if (connId.size() < quic::kMinConnectionIdSize) {
    throw quic::QuicInternalException(
        "ConnectionId is too small for hostid",
        quic::LocalErrorCode::INTERNAL_ERROR);
  }
  // clear 2 - 7 bits
  connId.data()[0] &= ~kHostIdFirstByteMask;
  // clear 8 - 15 bits
  connId.data()[1] &= ~kHostIdSecondByteMask;
  // clear 16 - 17 bits
  connId.data()[2] &= ~kHostIdThirdByteMask;

  // set 2 - 7 bits in the connId with the first 6 bits of the worker id
  connId.data()[0] |= (kHostIdFirstByteMask & (hostId >> 10));
  // set 8 - 15 bits in the connId with the next 8 bits of the worker id
  connId.data()[1] |= (kHostIdSecondByteMask & (hostId >> 2));
  // set 16 - 17 bits in the connId with the last 2 bits of the worker id
  connId.data()[2] |= (kHostIdThirdByteMask & (hostId << 6));
}

/**
 * Extract the host id bits [2 - 17] bits from the given ConnectionId
 */
uint16_t getHostIdBitsInConnId(const quic::ConnectionId& connId) {
  if (connId.size() < quic::kMinConnectionIdSize) {
    throw quic::QuicInternalException(
        "ConnectionId is too small for hostid",
        quic::LocalErrorCode::INTERNAL_ERROR);
  }
  uint16_t hostId = 0;
  // get 2 - 7 bits from the connId and set first 6 bits of the host id
  hostId = (kHostIdFirstByteMask & (connId.data()[0]));
  // shift by 10 bits and make room for the last 10 bits
  hostId = hostId << 10;
  // get 8 - 15 bits from the connId
  hostId |= (kHostIdSecondByteMask & connId.data()[1]) << 2;
  // get 16 - 17 bits from the connId
  hostId |= (kHostIdThirdByteMask & connId.data()[2]) >> 6;
  return hostId;
}

/**
 * Sets the given 8-bit workerId into the given connectionId's 18-25 bits
 */
void setWorkerIdBitsInConnId(quic::ConnectionId& connId, uint8_t workerId) {
  if (connId.size() < quic::kMinConnectionIdSize) {
    throw quic::QuicInternalException(
        "ConnectionId is too small for workerid",
        quic::LocalErrorCode::INTERNAL_ERROR);
  }
  // clear 18-23 bits
  connId.data()[2] &= 0xc0;
  // clear 24-25 bits
  connId.data()[3] &= 0x3f;
  // set 18 - 23 bits in the connId with first 6 bits of the worker id
  connId.data()[2] |= (kWorkerIdFirstByteMask & workerId) >> 2;
  // set 24 - 25 bits in the connId with the last 2 bits of the worker id
  connId.data()[3] |= (kWorkerIdSecondByteMask & workerId) << 6;
}

/**
 * Extracts the 'workerId' bits from the given ConnectionId
 */
uint8_t getWorkerIdFromConnId(const quic::ConnectionId& connId) {
  if (connId.size() < quic::kMinConnectionIdSize) {
    throw quic::QuicInternalException(
        "ConnectionId is too small for workerid",
        quic::LocalErrorCode::INTERNAL_ERROR);
  }
  // get 18 - 23 bits from the connId
  uint8_t workerId = connId.data()[2] << 2;
  // get 24 - 25 bits in the connId
  workerId |= connId.data()[3] >> 6;
  return workerId;
}

/**
 * Sets the server id bit (at 26th bit) into the given ConnectionId
 */
void setProcessIdBitsInConnId(quic::ConnectionId& connId, uint8_t processId) {
  if (connId.size() < quic::kMinConnectionIdSize) {
    throw quic::QuicInternalException(
        "ConnectionId is too small for processid",
        quic::LocalErrorCode::INTERNAL_ERROR);
  }
  // clear the 26th bit
  connId.data()[3] &= (~kProcessIdBitMask);
  connId.data()[3] |= (kProcessIdBitMask & (processId << 5));
}

/**
 * Extract the server id bit (at 26th bit) from the given ConnectionId
 */
uint8_t getProcessIdBitsFromConnId(const quic::ConnectionId& connId) {
  if (connId.size() < quic::kMinConnectionIdSize) {
    throw quic::QuicInternalException(
        "ConnectionId is too small for processid",
        quic::LocalErrorCode::INTERNAL_ERROR);
  }
  uint8_t processId = 0;
  processId = (kProcessIdBitMask & connId.data()[3]) >> 5;
  return processId;
}
} // namespace

namespace quic {

bool DefaultConnectionIdAlgo::canParse(const ConnectionId& id) const {
  if (id.size() < kMinConnectionIdSize) {
    return false;
  }
  return getVersionBitsFromConnId(id) == kShortVersionId;
}

ServerConnectionIdParams DefaultConnectionIdAlgo::parseConnectionId(
    const ConnectionId& id) {
  ServerConnectionIdParams serverConnIdParams(
      getVersionBitsFromConnId(id),
      getHostIdBitsInConnId(id),
      getProcessIdBitsFromConnId(id),
      getWorkerIdFromConnId(id));
  return serverConnIdParams;
}

ConnectionId DefaultConnectionIdAlgo::encodeConnectionId(
    const ServerConnectionIdParams& params) {
  // In case there is no client cid, create a random connection id.
  std::vector<uint8_t> connIdData(kDefaultConnectionIdSize);
  folly::Random::secureRandom(connIdData.data(), connIdData.size());
  ConnectionId connId = ConnectionId(std::move(connIdData));
  setVersionBitsInConnId(connId, params.version);
  setHostIdBitsInConnId(connId, params.hostId);
  setProcessIdBitsInConnId(connId, params.processId);
  setWorkerIdBitsInConnId(connId, params.workerId);
  return connId;
}

} // namespace quic
