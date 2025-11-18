/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/SocketAddress.h>

#include <quic/common/Expected.h>
#include <quic/common/Optional.h>
#include <quic/common/udpsocket/QuicAsyncUDPSocket.h>
#include <quic/congestion_control/CongestionController.h>

#include <memory>
#include <unordered_map>

namespace quic {

enum class PathStatus : uint8_t {
  NotValid, // New path or path that has previously failed validation
  Validating, // Path challenge sent
  Validated, // Path response received
};

struct QuicConnectionStateBase;

struct CachedCongestionControlAndRtt {
  // Time when this state is recorded, i.e. when migration happens
  TimePoint recordTime;

  // Congestion controller
  std::unique_ptr<CongestionController> congestionController;

  // Smooth rtt
  std::chrono::microseconds srtt{};
  // Latest rtt
  std::chrono::microseconds lrtt{};
  // Rtt var
  std::chrono::microseconds rttvar{};
  // Minimum rtt
  std::chrono::microseconds mrtt{};
};

struct PathInfo {
  PathIdType id;
  // Local address
  folly::SocketAddress localAddress;
  // Peer address
  folly::SocketAddress peerAddress;

  // If set, use this when writing packets on this path.
  // Otherwise, use the one used by the primary path.
  Optional<ConnectionId> destinationConnectionId;

  // Socket to use for writing.
  // If null, the existing transport's socket will be used.
  std::unique_ptr<QuicAsyncUDPSocket> socket;

  PathStatus status{PathStatus::NotValid};

  // If the path was validated through a path challenge, this is an RTT sample
  // from the challenge-reponse pair
  Optional<std::chrono::microseconds> rttSample;

  // If populated, this is the challenge we are scheduled to send to the peer
  Optional<uint64_t> outstandingChallengeData;
  // If validating, this is the timestamp the current challenge was first sent.
  // It is not updated on retransmissions.
  Optional<TimePoint> firstChallengeSentTimestamp;
  // If validating, this is the timestamp of the last time we sent the
  // outstanding challenge data. It is updated on retransmissions.
  Optional<TimePoint> lastChallengeSentTimestamp;
  // If validating, this is when we'd timeout and mark the path as not valid
  // if we haven't received a response
  Optional<TimePoint> pathResponseDeadline;
  // If validated, this is the timestamp of when the path was validated
  Optional<TimePoint> pathValidationTime;

  // If this is a server and this path is not validated, this is the number of
  // bytes we can send on this path.
  uint64_t writableBytes{0};

  // The congestion control and rtt state last time this path was used.
  // This won't be populated for the currently used path or for paths that
  // were never used.
  Optional<CachedCongestionControlAndRtt> cachedCCAndRttState;

  PathInfo() = delete;
  PathInfo(const PathInfo&) = delete;
  PathInfo& operator=(const PathInfo&) = delete;

  PathInfo(PathInfo&&) = default;
  PathInfo& operator=(PathInfo&&) noexcept = default;

  PathInfo(
      PathIdType idIn,
      folly::SocketAddress localAddressIn,
      folly::SocketAddress peerAddressIn,
      std::unique_ptr<QuicAsyncUDPSocket> socketIn,
      PathStatus statusIn)
      : id(idIn),
        localAddress(std::move(localAddressIn)),
        peerAddress(std::move(peerAddressIn)),
        socket(std::move(socketIn)),
        status(statusIn) {}

  ~PathInfo() = default;
};

/**
 * QuicPathManager manages the state of available paths for QUIC path probing
 * and connection migration functionality
 */
class QuicPathManager {
 private:
 public:
  class PathValidationCallback {
   public:
    virtual ~PathValidationCallback() = default;
    virtual void onPathValidationResult(const PathInfo& pathInfo) = 0;
  };

  explicit QuicPathManager(
      QuicConnectionStateBase& conn,
      PathValidationCallback* callback = nullptr);

  ~QuicPathManager() = default;

  // Non-copyable
  QuicPathManager(const QuicPathManager&) = delete;
  QuicPathManager& operator=(const QuicPathManager&) = delete;

  /**
   * Add a new path for the given address tuple.
   * Returns the PathId of the newly added path.
   */
  [[nodiscard]] quic::Expected<PathIdType, QuicError> addPath(
      const folly::SocketAddress& localAddress,
      const folly::SocketAddress& peerAddress,
      std::unique_ptr<QuicAsyncUDPSocket> socket = nullptr);

  /**
   * Add a new path for the given address tuple if it does not already exist.
   * Returns the PathInfo of the existing or the added path.
   */
  quic::Expected<std::reference_wrapper<const PathInfo>, QuicError>
  getOrAddPath(
      const folly::SocketAddress& localAddress,
      const folly::SocketAddress& peerAddress);

  /**
   * Add a new path that is already validated. This is used for the path used by
   * the connection during the handshake. Returns the PathId of the newly
   * added path.
   */
  [[nodiscard]] quic::Expected<PathIdType, QuicError> addValidatedPath(
      const folly::SocketAddress& localAddress,
      const folly::SocketAddress& peerAddress);

  /**
   * Remove a path by PathId.
   * Returns an error if the path does not exist or if it's the current path for
   * the connection.
   */
  [[nodiscard]] quic::Expected<void, QuicError> removePath(PathIdType pathId);

  /**
   * Get path information by PathId.
   * Returns PathInfo* or nullptr if not found.
   */
  const PathInfo* getPath(PathIdType pathId) const;

  /**
   * Get path information for the given path address tuple.
   * Returns PathInfo* or nullptr if not found.
   */
  const PathInfo* getPath(
      const folly::SocketAddress& localAddress,
      const folly::SocketAddress& peerAddress);

  /**
   * Get new path challenge data for the given path.
   * Returns a uint64_t containing the challenge data or an error if the path
   * doesn't exist. If there is a pending challenge, the outstanding challenge
   * data is discarded.
   */
  Expected<uint64_t, QuicError> getNewPathChallengeData(PathIdType pathId);

  const PathInfo* getPathByChallengeData(uint64_t challengeData);

  /**
   * Update the state with a PathChallengeFrame that was sent
   */
  void onPathChallengeSent(const PathChallengeFrame& frame);

  /**
   * Update the state when the path validation timeout expires.
   */
  void onPathValidationTimeoutExpired(TimePoint now = Clock::now());

  /**
   * Update the state with a PathResponseFrame that was received. Returns the
   * validated path if any
   */
  const PathInfo* onPathResponseReceived(
      const PathResponseFrame& frame,
      PathIdType incomingPathId);

  /**
   * Get the earliest time when a pending path validation timeout should fail
   */
  Optional<TimePoint> getEarliestChallengeTimeout() const;

  /*
   * Set the callback to be invoked when a path validation succeeds or fails.
   */
  void setPathValidationCallback(PathValidationCallback* callback);

  /*
   * Cache the congestion control and rtt state of the current path.
   */
  void cacheCurrentCongestionAndRttState();

  /*
   * Assign a destination connection id for the given path. This will be one of
   * the peer's destination connection ids.
   */
  Expected<void, QuicError> assignDestinationCidForPath(PathIdType pathId);

  /*
   * Set the given destination connection id for the specified path.
   */
  Expected<void, QuicError> setDestinationCidForPath(
      PathIdType pathId,
      ConnectionId cid);

  /*
   * Restores the congestion control and rtt state of the current path from
   * the cached state. If no state is cached for the current path, this will
   * reset the rtt state to the default and signal the caller to reset the
   * congestion controller.
   *
   * Returns true, if a congestion controller is restored.
   * If it returns false, the caller is responsible for resetting the
   * congestion controller.
   */
  [[nodiscard]] bool maybeRestoreCongestionControlAndRttStateForCurrentPath();

  /*
   * Mark path as validated
   */
  void markPathValidated(PathIdType pathId);

  /*
   * Functions to updating the writable bytes limit.
   * These are only required for unvalidated paths.
   */
  void onPathPacketSent(PathIdType pathId, uint16_t encodedPacketSize);
  void onPathPacketReceived(PathIdType pathId);

  /*
   * Drop any sockets tracked by the path manager. This will pause reading from
   * all the sockets and destroy them.
   */
  void dropAllSockets();

  /*
   * Update an existing path with a socket. This is useful for tracking an old
   * path after migration in case it needs to be restored later.
   */
  [[nodiscard]] quic::Expected<void, QuicError> addSocketToPath(
      PathIdType pathId,
      std::unique_ptr<QuicAsyncUDPSocket> socket);

  [[nodiscard]] quic::Expected<std::unique_ptr<QuicAsyncUDPSocket>, QuicError>
  switchCurrentPath(PathIdType switchToPathId);

  /*
   * If the number of tracked paths is equal to the maximum number of active
   * connection ids, this will delete the oldest path besides the one the
   * connection is currently using, and retire its connection id.
   * This is useful for the server to leave headroom for an incoming migration
   * attempt. This is because the server needs to use a new peer CID when on any
   * migration path.
   */
  void maybeReapUnusedPaths(bool force = false);

 private:
  friend class PathManagerTestAccessor;

  PathInfo* getPathByChallengeDataImpl(uint64_t challengeData);

  // Map from PathId to PathInfo
  // Note: This uses a stable reference container
  UnorderedNodeMap<PathIdType, PathInfo> pathIdToInfo_;

  // localAddress, peerAddress
  using PathAddressTuple =
      std::pair<folly::SocketAddress, folly::SocketAddress>;

  // Map from PathAddressTuple to PathId
  UnorderedMap<PathAddressTuple, PathIdType> pathTupleToId_;

  // Deque of paths that have sent a challenge and are waiting for a response.
  // They are ordered by the time the challenge was sent, earliest in front.
  // This is used to determine the next challenge timeout.
  std::deque<PathIdType> pathsPendingResponse_;

  // Counter for generating unique PathId
  PathIdType nextPathId_;

  // Connection state
  QuicConnectionStateBase& conn_;

  // Generate a unique PathId
  PathIdType generatePathId();

  // The path validation callback
  PathValidationCallback* pathValidationCallback_{nullptr};

  // The latest retrieved path is cached here. This is an optimization to reduce
  // looking up the path by source,destination tuple or by id in the maps for
  // every read and write.
  mutable const PathInfo* cachedPath_{nullptr};
};

} // namespace quic
