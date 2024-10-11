/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/codec/Types.h>

namespace quic {

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

} // namespace quic
