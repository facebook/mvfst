/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>

#include <folly/String.h>
#include <folly/hash/Hash.h>
#include <folly/io/Cursor.h>
#include <folly/io/IOBuf.h>

#include <array>

#include <quic/QuicConstants.h>

namespace quic {
constexpr uint8_t kStatelessResetTokenLength = 16;
using StatelessResetToken = std::array<uint8_t, kStatelessResetTokenLength>;

// max size of a connId as specified in the draft
constexpr size_t kMaxConnectionIdSize = 20;

// Minimum required length (in bytes) for the destination connection-id
// on inbound initial packets.
constexpr size_t kMinInitialDestinationConnIdLength = 8;

constexpr uint64_t kInitialSequenceNumber = 0x0;

// First two bits of CID is version
enum class ConnectionIdVersion : uint8_t { V0 = 0, V1 = 1, V2 = 2, V3 = 3 };

struct ConnectionId {
  uint8_t* data();

  const uint8_t* data() const;

  uint8_t size() const;

  explicit ConnectionId(const std::vector<uint8_t>& connidIn);

  explicit ConnectionId(folly::io::Cursor& cursor, size_t len);

  bool operator==(const ConnectionId& other) const;
  bool operator!=(const ConnectionId& other) const;

  std::string hex() const;

  /**
   * Create an connection without any checks for tests.
   */
  static ConnectionId createWithoutChecks(const std::vector<uint8_t>& connidIn);

  /**
   * Create a random ConnectionId with the given length.
   */
  static ConnectionId createRandom(size_t len);

 private:
  ConnectionId() = default;

  std::array<uint8_t, kMaxConnectionIdSize> connid;
  uint8_t connidLen;
};

struct ConnectionIdHash {
  size_t operator()(const ConnectionId& connId) const {
    return folly::hash::fnv32_buf(connId.data(), connId.size());
  }
};

inline std::ostream& operator<<(std::ostream& os, const ConnectionId& connId) {
  os << connId.hex();
  return os;
}

inline folly::IOBuf toData(const ConnectionId& connId) {
  return folly::IOBuf::wrapBufferAsValue(connId.data(), connId.size());
}

struct ConnectionIdData {
  ConnectionIdData(const ConnectionId& connIdIn, uint64_t sequenceNumberIn)
      : connId(connIdIn), sequenceNumber(sequenceNumberIn) {}

  ConnectionIdData(
      const ConnectionId& connIdIn,
      uint64_t sequenceNumberIn,
      StatelessResetToken tokenIn)
      : connId(connIdIn), sequenceNumber(sequenceNumberIn), token(tokenIn) {}

  ConnectionId connId;
  uint64_t sequenceNumber;
  folly::Optional<StatelessResetToken> token;
};

/**
 * Encapsulate parameters to generate server chosen connection id
 */
struct ServerConnectionIdParams {
  explicit ServerConnectionIdParams(
      uint32_t hostIdIn,
      uint8_t processIdIn,
      uint8_t workerIdIn)
      : ServerConnectionIdParams(
            ConnectionIdVersion::V1,
            hostIdIn,
            processIdIn,
            workerIdIn) {}

  explicit ServerConnectionIdParams(
      ConnectionIdVersion versionIn,
      uint32_t hostIdIn,
      uint8_t processIdIn,
      uint8_t workerIdIn) {
    setVersion(versionIn);
    setHostId(hostIdIn);
    setProcessId(processIdIn);
    setWorkerId(workerIdIn);
  }

  /**
   * Set Quic connection-id short version
   */
  void setVersion(ConnectionIdVersion versionIn);

  /**
   * Set Quic Host id
   * Depending on version, lower 2 or 3 bytes used
   */
  void setHostId(uint32_t hostIdIn);

  /**
   * Set Quic process id
   */
  void setProcessId(uint8_t processIdIn);

  /**
   * Set Quic server worker Id
   */
  void setWorkerId(uint8_t workerIdIn);

  // Quic connection-id short version
  ConnectionIdVersion version{ConnectionIdVersion::V0};
  // Quic Host id
  uint32_t hostId{0};
  // Quic process id
  uint8_t processId{0};
  // Quic server worker Id
  uint8_t workerId{0};
};

bool operator==(
    const ServerConnectionIdParams& lhs,
    const ServerConnectionIdParams& rhs);

bool operator!=(
    const ServerConnectionIdParams& lhs,
    const ServerConnectionIdParams& rhs);

} // namespace quic
