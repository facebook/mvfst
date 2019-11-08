/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Optional.h>
#include <folly/functional/Invoke.h>
#include <folly/io/async/EventBase.h>
#include <string>

namespace quic {

/* Interface for Transport level stats per VIP (server)
 * Quic Transport expects applications to instantiate this per thread (and
 * do necessary aggregation at the application level).
 *
 * NOTE: since several of these methods are called for every single packets,
 * and every single connection, it is extremely important to not do any
 * blocking call in any of the implementation of these methods.
 */
class QuicTransportStatsCallback {
 public:
  enum class PacketDropReason : uint8_t {
    NONE,
    CONNECTION_NOT_FOUND,
    DECRYPTION_ERROR,
    INVALID_PACKET,
    PARSE_ERROR,
    PEER_ADDRESS_CHANGE,
    PROTOCOL_VIOLATION,
    ROUTING_ERROR_WRONG_HOST,
    SERVER_STATE_CLOSED,
    TRANSPORT_PARAMETER_ERROR,
    WORKER_NOT_INITIALIZED,
    SERVER_SHUTDOWN,
    INITIAL_CONNID_SMALL,
    // NOTE: MAX should always be at the end
    MAX
  };

  enum class ConnectionCloseReason : uint8_t {
    NONE,
    CONN_ERROR,
    IDLE_TIMEOUT,
    // NOTE: MAX should always be at the end
    MAX
  };

  enum class SocketErrorType : uint8_t {
    AGAIN,
    INVAL,
    MSGSIZE,
    NOBUFS,
    NOMEM,
    OTHER,
    MAX
  };

  virtual ~QuicTransportStatsCallback() = default;

  // packet level metrics
  virtual void onPacketReceived() = 0;

  virtual void onDuplicatedPacketReceived() = 0;

  virtual void onOutOfOrderPacketReceived() = 0;

  virtual void onPacketProcessed() = 0;

  virtual void onPacketSent() = 0;

  virtual void onPacketRetransmission() = 0;

  virtual void onPacketDropped(PacketDropReason reason) = 0;

  virtual void onPacketForwarded() = 0;

  virtual void onForwardedPacketReceived() = 0;

  virtual void onForwardedPacketProcessed() = 0;

  // connection level metrics:
  virtual void onNewConnection() = 0;

  virtual void onConnectionClose(
      folly::Optional<ConnectionCloseReason> reason = folly::none) = 0;

  // stream level metrics
  virtual void onNewQuicStream() = 0;

  virtual void onQuicStreamClosed() = 0;

  virtual void onQuicStreamReset() = 0;

  // flow control / congestion control / loss recovery related metrics
  virtual void onConnFlowControlUpdate() = 0;

  virtual void onConnFlowControlBlocked() = 0;

  virtual void onStatelessReset() = 0;

  virtual void onStreamFlowControlUpdate() = 0;

  virtual void onStreamFlowControlBlocked() = 0;

  virtual void onCwndBlocked() = 0;

  // retransmission timeout counter
  virtual void onPTO() = 0;

  // metrics to track bytes read from / written to wire
  virtual void onRead(size_t bufSize) = 0;

  virtual void onWrite(size_t bufSize) = 0;

  virtual void onUDPSocketWriteError(SocketErrorType errorType) = 0;

  static const char* toString(ConnectionCloseReason reason) {
    switch (reason) {
      case ConnectionCloseReason::NONE:
        return "NONE";
      case ConnectionCloseReason::CONN_ERROR:
        return "CONN_ERROR";
      case ConnectionCloseReason::IDLE_TIMEOUT:
        return "IDLE_TIMEOUT";
      case ConnectionCloseReason::MAX:
        return "MAX";
      default:
        throw std::runtime_error("Undefined ConnectionCloseReason passed");
    }
  }

  static const char* toString(PacketDropReason reason) {
    switch (reason) {
      case PacketDropReason::NONE:
        return "NONE";
      case PacketDropReason::CONNECTION_NOT_FOUND:
        return "CONNECTION_NOT_FOUND";
      case PacketDropReason::DECRYPTION_ERROR:
        return "DECRYPTION_ERROR";
      case PacketDropReason::INVALID_PACKET:
        return "INVALID_PACKET";
      case PacketDropReason::PARSE_ERROR:
        return "PARSE_ERROR";
      case PacketDropReason::PEER_ADDRESS_CHANGE:
        return "PEER_ADDRESS_CHANGE";
      case PacketDropReason::PROTOCOL_VIOLATION:
        return "PROTOCOL_VIOLATION";
      case PacketDropReason::ROUTING_ERROR_WRONG_HOST:
        return "ROUTING_ERROR_WRONG_HOST";
      case PacketDropReason::SERVER_STATE_CLOSED:
        return "SERVER_STATE_CLOSED";
      case PacketDropReason::TRANSPORT_PARAMETER_ERROR:
        return "TRANSPORT_PARAMETER_ERROR";
      case PacketDropReason::WORKER_NOT_INITIALIZED:
        return "WORKER_NOT_INITIALIZED";
      case PacketDropReason::SERVER_SHUTDOWN:
        return "SERVER_SHUTDOWN";
      case PacketDropReason::INITIAL_CONNID_SMALL:
        return "INITIAL_CONNID_SMALL";
      case PacketDropReason::MAX:
        return "MAX";
      default:
        throw std::runtime_error("Undefined PacketDropReason passed");
    }
  }

  static const char* toString(SocketErrorType errorType) {
    switch (errorType) {
      case SocketErrorType::AGAIN:
        return "AGAIN";
      case SocketErrorType::INVAL:
        return "INVAL";
      case SocketErrorType::MSGSIZE:
        return "MSGSIZE";
      case SocketErrorType::NOBUFS:
        return "NOBUFS";
      case SocketErrorType::NOMEM:
        return "NOMEM";
      case SocketErrorType::OTHER:
        return "Other";
      default:
        throw std::runtime_error("Undefined SocketErrorType");
    }
  }

  static SocketErrorType errnoToSocketErrorType(int err) {
    switch (err) {
      case EAGAIN:
        return SocketErrorType::AGAIN;
      case EINVAL:
        return SocketErrorType::INVAL;
      case EMSGSIZE:
        return SocketErrorType::MSGSIZE;
      case ENOBUFS:
        return SocketErrorType::NOBUFS;
      case ENOMEM:
        return SocketErrorType::NOMEM;
      default:
        return SocketErrorType::OTHER;
    }
  }
};

/**
 * Interface to create QuicTransportStatsCallback instance.
 * If application supplies the implementation of this factory, the transport
 * calls 'make' during its initialization _for each worker_.
 * Further, 'make' is called from the worker's eventbase so that it is
 * convenient for application to specify actions such as scheduling per thread
 * aggregation
 */
class QuicTransportStatsCallbackFactory {
 public:
  virtual ~QuicTransportStatsCallbackFactory() = default;

  virtual std::unique_ptr<QuicTransportStatsCallback> make(
      folly::EventBase* evb) = 0;
};

#define QUIC_STATS(infoCallback, method, ...)                              \
  if (infoCallback) {                                                      \
    folly::invoke(                                                         \
        &QuicTransportStatsCallback::method, infoCallback, ##__VA_ARGS__); \
  }

#define QUIC_STATS_FOR_EACH(iterBegin, iterEnd, infoCallback, method, ...)   \
  if (infoCallback) {                                                        \
    std::for_each(iterBegin, iterEnd, [&](const auto&) {                     \
      folly::invoke(                                                         \
          &QuicTransportStatsCallback::method, infoCallback, ##__VA_ARGS__); \
    });                                                                      \
  }
} // namespace quic
