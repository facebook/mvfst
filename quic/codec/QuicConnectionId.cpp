/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.
#include <quic/codec/QuicConnectionId.h>
#include <glog/logging.h>
#include <quic/QuicConstants.h>

namespace quic {

uint8_t* ConnectionId::data() {
  return connid.data();
}

const uint8_t* ConnectionId::data() const {
  return connid.data();
}

uint8_t ConnectionId::size() const {
  return static_cast<uint8_t>(connid.size());
}

std::string ConnectionId::hex() const {
  return folly::hexlify(connid);
}

ConnectionId::ConnectionId(const std::vector<uint8_t>& connidIn)
    : connid(connidIn) {
  static_assert(
      std::numeric_limits<uint8_t>::max() > kMaxConnectionIdSize,
      "Max connection size is too big");
  if (connid.size() != 0 &&
      (connid.size() < kMinConnectionIdSize ||
       connid.size() > kMaxConnectionIdSize)) {
    // We can't throw a transport error here because of the dependency. This is
    // sad because this will cause an internal error downstream.
    throw std::runtime_error("ConnectionId invalid size");
  }
}

ConnectionId::ConnectionId(folly::io::Cursor& cursor, size_t len) {
  // Zero is special case for connids.
  if (len == 0) {
    return;
  }
  if (len < kMinConnectionIdSize || len > kMaxConnectionIdSize) {
    // We can't throw a transport error here because of the dependency. This is
    // sad because this will cause an internal error downstream.
    throw std::runtime_error("ConnectionId invalid size");
  }
  connid.resize(len);
  cursor.pull(connid.data(), len);
}

ConnectionId ConnectionId::createWithoutChecks(
    const std::vector<uint8_t>& connidIn) {
  ConnectionId connid;
  connid.connid = connidIn;
  return connid;
}

bool ConnectionId::operator==(const ConnectionId& other) const {
  return connid == other.connid;
}

bool ConnectionId::operator!=(const ConnectionId& other) const {
  return !operator==(other);
}

void ServerConnectionIdParams::setVersion(uint8_t versionIn) {
  version = versionIn;
}

void ServerConnectionIdParams::setHostId(uint16_t hostIdIn) {
  hostId = hostIdIn;
}

void ServerConnectionIdParams::setProcessId(uint8_t processIdIn) {
  processId = processIdIn;
}

void ServerConnectionIdParams::setWorkerId(uint8_t workerIdIn) {
  workerId = workerIdIn;
}

std::pair<uint8_t, uint8_t> decodeConnectionIdLengths(uint8_t connIdSize) {
  uint8_t dcidLen = (connIdSize >> 4);
  uint8_t scidLen = connIdSize & 0x0F;
  dcidLen = dcidLen == 0 ? 0 : dcidLen + 3;
  scidLen = scidLen == 0 ? 0 : scidLen + 3;
  return std::make_pair(dcidLen, scidLen);
}

uint8_t encodeConnectionIdLengths(
    uint8_t destinationConnectionIdSize,
    uint8_t sourceConnectionIdSize) {
  DCHECK_LE(destinationConnectionIdSize, kMaxConnectionIdSize);
  DCHECK_LE(sourceConnectionIdSize, kMaxConnectionIdSize);
  uint8_t dstByte =
      destinationConnectionIdSize == 0 ? 0 : destinationConnectionIdSize - 3;
  uint8_t srcByte =
      sourceConnectionIdSize == 0 ? 0 : sourceConnectionIdSize - 3;
  return ((dstByte << 4)) | (srcByte);
}
} // namespace quic
