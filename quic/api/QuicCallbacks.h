/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicException.h>

namespace quic {

using StreamId = uint64_t;
using StreamGroupId = uint64_t;

/**
 * Callback class for receiving data on a stream
 */
class StreamReadCallback {
 public:
  virtual ~StreamReadCallback() = default;

  /**
   * Called from the transport layer when there is data, EOF or an error
   * available to read on the given stream ID
   */
  virtual void readAvailable(StreamId id) noexcept = 0;

  /*
   * Same as above, but called on streams within a group.
   */
  virtual void readAvailableWithGroup(StreamId, StreamGroupId) noexcept {}

  /**
   * Called from the transport layer when there is an error on the stream.
   */
  virtual void readError(StreamId id, QuicError error) noexcept = 0;

  /**
   * Same as above, but called on streams within a group.
   */
  virtual void readErrorWithGroup(StreamId, StreamGroupId, QuicError) noexcept {
  }
};

/**
 * Callback class for receiving write readiness notifications
 */
class StreamWriteCallback {
 public:
  virtual ~StreamWriteCallback() = default;

  /**
   * Invoked when stream is ready to write after notifyPendingWriteOnStream
   * has previously been called.
   *
   * maxToSend represents the amount of data that the transport layer expects
   * to write to the network during this event loop, eg:
   *   min(remaining flow control, remaining send buffer space)
   */
  virtual void onStreamWriteReady(
      StreamId /* id */,
      uint64_t /* maxToSend */) noexcept {}

  /**
   * Invoked when a connection is being torn down after
   * notifyPendingWriteOnStream has been called
   */
  virtual void onStreamWriteError(
      StreamId /* id */,
      QuicError /* error */) noexcept {}
};

/**
 * Callback class for receiving write readiness notifications
 */
class ConnectionWriteCallback {
 public:
  virtual ~ConnectionWriteCallback() = default;

  /**
   * Invoked when connection is ready to write after
   * notifyPendingWriteOnConnection has previously been called.
   *
   * maxToSend represents the amount of data that the transport layer expects
   * to write to the network during this event loop, eg:
   *   min(remaining flow control, remaining send buffer space)
   */
  virtual void onConnectionWriteReady(uint64_t /* maxToSend */) noexcept {}

  /**
   * Invoked when a connection is being torn down after
   * notifyPendingWriteOnConnection has been called
   */
  virtual void onConnectionWriteError(QuicError
                                      /* error */) noexcept {}
};

/**
 * Structure used to communicate TX and ACK/Delivery notifications.
 */
struct ByteEvent {
  enum class Type { ACK = 1, TX = 2 };
  static constexpr std::array<Type, 2> kByteEventTypes = {
      {Type::ACK, Type::TX}};

  StreamId id{0};
  uint64_t offset{0};
  Type type;

  // sRTT at time of event
  // TODO(bschlinker): Deprecate, caller can fetch transport state if
  // desired.
  std::chrono::microseconds srtt{0us};
};

/**
 * Structure used to communicate cancellation of a ByteEvent.
 *
 * According to Dictionary.com, cancellation is more frequent in American
 * English than cancellation. Yet in American English, the preferred style is
 * typically not to double the final L, so cancel generally becomes canceled.
 */
using ByteEventCancellation = ByteEvent;

/**
 * Callback class for receiving byte event (TX/ACK) notifications.
 */
class ByteEventCallback {
 public:
  virtual ~ByteEventCallback() = default;

  /**
   * Invoked when a byte event has been successfully registered.
   * Since this is a convenience notification and not a mandatory callback,
   * not marking this as pure virtual.
   */
  virtual void onByteEventRegistered(ByteEvent /* byteEvent */) {}

  /**
   * Invoked when the byte event has occurred.
   */
  virtual void onByteEvent(ByteEvent byteEvent) = 0;

  /**
   * Invoked if byte event is canceled due to reset, shutdown, or other error.
   */
  virtual void onByteEventCanceled(ByteEventCancellation cancellation) = 0;
};

} // namespace quic
