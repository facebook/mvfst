/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/MaybeManagedPtr.h>
#include <folly/Portability.h>
#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>
#include <quic/api/QuicSocketLite.h>
#include <quic/common/FunctionRef.h>
#include <quic/common/Optional.h>
#include <quic/common/events/QuicEventBase.h>
#include <quic/observer/SocketObserverContainer.h>
#include <quic/priority/PriorityQueue.h>
#include <chrono>

namespace quic {

class QuicSocket : virtual public QuicSocketLite {
 public:
  /**
   * Sets the functions that mvfst will invoke to validate early data params
   * and encode early data params to NewSessionTicket.
   * It's up to the application's responsibility to make sure captured objects
   * (if any) are alive when the functions are called.
   *
   * validator:
   *   On server side:
   *     Called during handshake while negotiating early data.
   *     @param alpn
   *       The negotiated ALPN. Optional because it may be absent from
   *       ClientHello.
   *     @param appParams
   *       The encoded and encrypted application parameters from PSK.
   *     @return
   *       Whether application accepts parameters from resumption state for
   *       0-RTT.
   *   On client side:
   *     Called when transport is applying psk from cache.
   *     @param alpn
   *       The ALPN client is going to use for this connection. Optional
   *       because client may not set ALPN.
   *     @param appParams
   *       The encoded (not encrypted) application parameter from local cache.
   *     @return
   *       Whether application will attempt early data based on the cached
   *       application parameters. This is useful when client updates to use a
   *       new binary but still reads PSK from an old cache. Client may choose
   *       to not attempt 0-RTT at all given client thinks server will likely
   *       reject it.
   *
   * getter:
   *   On server side:
   *     Called when transport is writing NewSessionTicket.
   *     @return
   *       The encoded application parameters that will be included in
   *       NewSessionTicket.
   *   On client side:
   *     Called when client receives NewSessionTicket and is going to write to
   *     cache.
   *     @return
   *       Encoded application parameters that will be written to cache.
   */
  virtual void setEarlyDataAppParamsFunctions(
      std::function<
          bool(const Optional<std::string>& alpn, const BufPtr& appParams)>
          validator,
      std::function<BufPtr()> getter) = 0;

  ~QuicSocket() override = default;

  /**
   * ===== Generic Socket Methods =====
   */

  /**
   * Get the QUIC Client Connection ID
   */
  [[nodiscard]] virtual Optional<ConnectionId> getClientConnectionId()
      const = 0;

  /**
   * Get the QUIC Server Connection ID
   */
  [[nodiscard]] virtual Optional<ConnectionId> getServerConnectionId()
      const = 0;

  /**
   * Get the original Quic Server Connection ID chosen by client
   */
  [[nodiscard]] virtual Optional<ConnectionId> getClientChosenDestConnectionId()
      const = 0;

  [[nodiscard]] virtual bool replaySafe() const = 0;

  /**
   * Close this socket gracefully, by waiting for all the streams to be idle
   * first.
   */
  virtual void closeGracefully() = 0;

  /**
   * Returns the current offset already read or written by the application on
   * the given stream.
   */
  [[nodiscard]] virtual quic::Expected<size_t, LocalErrorCode>
  getStreamReadOffset(StreamId id) const = 0;
  [[nodiscard]] virtual quic::Expected<size_t, LocalErrorCode>
  getStreamWriteOffset(StreamId id) const = 0;
  /**
   * Returns the amount of data buffered by the transport waiting to be written
   */
  [[nodiscard]] virtual quic::Expected<size_t, LocalErrorCode>
  getStreamWriteBufferedBytes(StreamId id) const = 0;

  /**
   * Returns the current flow control windows for the connection.
   * Use getStreamFlowControl for stream flow control window.
   */
  [[nodiscard]] virtual quic::Expected<FlowControlState, LocalErrorCode>
  getConnectionFlowControl() const = 0;

  /**
   * Returns the minimum of current send flow control window and available
   * buffer space.
   */
  [[nodiscard]] virtual quic::Expected<uint64_t, LocalErrorCode>
  getMaxWritableOnStream(StreamId id) const = 0;

  /**
   * Sets the flow control window for the connection.
   * Use setStreamFlowControlWindow for per Stream flow control.
   */
  virtual quic::Expected<void, LocalErrorCode> setConnectionFlowControlWindow(
      uint64_t windowSize) = 0;

  /**
   * Sets the flow control window for the stream.
   * Use setConnectionFlowControlWindow for connection flow control.
   */
  virtual quic::Expected<void, LocalErrorCode> setStreamFlowControlWindow(
      StreamId id,
      uint64_t windowSize) = 0;

  /**
   * Get stream priority.
   */
  virtual quic::Expected<PriorityQueue::Priority, LocalErrorCode>
  getStreamPriority(StreamId id) = 0;

  /**
   * Convenience function that sets the read callbacks of all streams to be
   * nullptr.
   */
  virtual void unsetAllReadCallbacks() = 0;

  /**
   * Convenience function that sets the read callbacks of all streams to be
   * nullptr.
   */
  virtual void unsetAllPeekCallbacks() = 0;

  /**
   * Convenience function that cancels delivery callbacks of all streams.
   */
  virtual void unsetAllDeliveryCallbacks() = 0;

  /**
   * Pause/Resume read callback being triggered when data is available.
   */
  virtual quic::Expected<void, LocalErrorCode> pauseRead(StreamId id) = 0;
  virtual quic::Expected<void, LocalErrorCode> resumeRead(StreamId id) = 0;

  /**
   * ===== Peek/Consume API =====
   */

  class PeekCallback {
   public:
    virtual ~PeekCallback() = default;

    /**
     * Called from the transport layer when there is new data available to
     * peek on a given stream.
     * Callback can be called multiple times and it is up to application to
     * de-dupe already peeked ranges.
     */
    virtual void onDataAvailable(
        StreamId id,
        const folly::Range<PeekIterator>& peekData) noexcept = 0;

    /**
     * Called from the transport layer during peek time when there is an error
     * on the stream.
     */
    virtual void peekError(StreamId id, QuicError error) noexcept = 0;
  };

  /**
   * Callback class for pings
   */
  class PingCallback {
   public:
    virtual ~PingCallback() = default;

    /**
     * Invoked when the ping is acknowledged
     */
    virtual void pingAcknowledged() noexcept = 0;

    /**
     * Invoked if the ping times out
     */
    virtual void pingTimeout() noexcept = 0;

    /**
     * Invoked when a ping is received
     */
    virtual void onPing() noexcept = 0;
  };

  /**
   * Callback class for datagrams
   */
  class DatagramCallback {
   public:
    virtual ~DatagramCallback() = default;

    /**
     * Notifies the DatagramCallback that datagrams are available for read.
     */
    virtual void onDatagramsAvailable() noexcept = 0;
  };

  virtual quic::Expected<void, LocalErrorCode> setPeekCallback(
      StreamId id,
      PeekCallback* cb) = 0;

  /**
   * Pause/Resume peek callback being triggered when data is available.
   */
  virtual quic::Expected<void, LocalErrorCode> pausePeek(StreamId id) = 0;
  virtual quic::Expected<void, LocalErrorCode> resumePeek(StreamId id) = 0;

  /**
   * Peek at the given stream.
   *
   * The return value is Expected.  If the value hasError(), then a read error
   * occurred and it can be obtained with error().  If the value hasValue(),
   * indicates that peekCallback has been called.
   *
   * The range that is passed to callback is only valid until callback returns,
   * If caller need to preserve data that range points to - that data has to
   * be copied.
   *
   * Calling peek() when there is no data/eof to deliver will return an
   * EAGAIN-like error code.
   */
  virtual quic::Expected<void, LocalErrorCode> peek(
      StreamId id,
      FunctionRef<void(StreamId id, const folly::Range<PeekIterator>&)>
          peekCallback) = 0;

  /**
   * Consumes data on the given stream, starting from currentReadOffset
   *
   * The return value is Expected.  If the value hasError(), then a read error
   * occurred and it can be obtained with error().
   *
   * @offset - represents start of consumed range.
   * Current implementation returns error and currentReadOffset if offset !=
   * currentReadOffset
   *
   * Calling consume() when there is no data/eof to deliver
   * will return an EAGAIN-like error code.
   *
   */
  virtual quic::Expected<void, std::pair<LocalErrorCode, Optional<uint64_t>>>
  consume(StreamId id, uint64_t offset, size_t amount) = 0;

  /**
   * Equivalent of calling consume(id, stream->currentReadOffset, amount);
   */
  virtual quic::Expected<void, LocalErrorCode> consume(
      StreamId id,
      size_t amount) = 0;

  /**
   * Returns whether a stream ID represents a client-initiated stream.
   */
  virtual bool isClientStream(StreamId stream) noexcept = 0;

  /**
   * Returns whether a stream ID represents a server-initiated stream.
   */
  virtual bool isServerStream(StreamId stream) noexcept = 0;

  /**
   * Returns directionality (unidirectional or bidirectional) of a stream by ID.
   */
  virtual StreamDirectionality getStreamDirectionality(
      StreamId stream) noexcept = 0;

  /**
   * Register a callback to be invoked when the stream offset was transmitted.
   *
   * Currently, an offset is considered "transmitted" if it has been written to
   * to the underlying UDP socket, indicating that it has passed through
   * congestion control and pacing. In the future, this callback may be
   * triggered by socket/NIC software or hardware timestamps.
   *
   * If the registration fails, the callback (ByteEventCallback* cb) will NEVER
   * be invoked for anything. If the registration succeeds, the callback is
   * guaranteed to receive an onByteEventRegistered() notification.
   */
  virtual quic::Expected<void, LocalErrorCode> registerTxCallback(
      const StreamId id,
      const uint64_t offset,
      ByteEventCallback* cb) = 0;

  /**
   * Reset or send a stop sending on all non-control streams. Leaves the
   * connection otherwise unmodified. Note this will also trigger the
   * onStreamWriteError and readError callbacks immediately.
   */
  virtual void resetNonControlStreams(
      ApplicationErrorCode error,
      folly::StringPiece errorMsg) = 0;

  /**
   * Helper method to check a generic error for an Application error, and reset
   * the stream with the reciprocal error.
   *
   * Returns true if the error was an ApplicationErrorCode, and the stream was
   * reset.
   */
  virtual quic::Expected<void, LocalErrorCode> maybeResetStreamFromReadError(
      StreamId id,
      QuicErrorCode error) = 0;

  /**
   * This is used in conjunction with reliable resets. When we send data on a
   * stream and want to mark which offset will constitute the reliable size in a
   * future call to resetStreamReliably, we call this function. This function
   * can potentially be called multiple times on a stream to advance the offset,
   * but it is an error to call it after sending a reset.
   */
  virtual quic::Expected<void, LocalErrorCode> updateReliableDeliveryCheckpoint(
      StreamId id) = 0;

  /**
   * Send a reliable reset to the peer. The reliable size sent to the peer is
   * determined by when checkpoint(streamId) was last called.
   */
  virtual quic::Expected<void, LocalErrorCode> resetStreamReliably(
      StreamId id,
      ApplicationErrorCode error) = 0;

  /**
   * Set the ping callback
   */
  virtual quic::Expected<void, LocalErrorCode> setPingCallback(
      PingCallback* cb) = 0;

  /**
   * Send a ping to the peer.  When the ping is acknowledged by the peer or
   * times out, the transport will invoke the callback.
   */
  virtual void sendPing(std::chrono::milliseconds pingTimeout) = 0;

  /**
   * Detaches the eventbase from the socket. This must be called from the
   * eventbase of socket.
   * Normally this is invoked by an app when the connection is idle, i.e.
   * there are no "active" streams on the connection, however an app might
   * think that all the streams are closed because it wrote the FIN
   * to the QuicSocket, however the QuicSocket might not have delivered the FIN
   * to the peer yet. Apps SHOULD use the delivery callback to make sure that
   * all writes for the closed stream are finished before detaching the
   * connection from the eventbase.
   */
  virtual void detachEventBase() = 0;

  /**
   * Attaches an eventbase to the socket. This must be called from the
   * eventbase that needs to be attached and the caller must make sure that
   * there is no eventbase already attached to the socket.
   */
  virtual void attachEventBase(std::shared_ptr<QuicEventBase> evb) = 0;

  /**
   * Returns whether or not the eventbase can currently be detached from the
   * socket.
   */
  virtual bool isDetachable() = 0;

  /**
   * ===== Datagram API =====
   *
   * Datagram support is experimental. Currently there isn't delivery callback
   * or loss notification support for Datagram.
   */

  /**
   * Set the read callback for Datagrams
   */
  virtual quic::Expected<void, LocalErrorCode> setDatagramCallback(
      DatagramCallback* cb) = 0;

  /**
   * Returns the maximum allowed Datagram payload size.
   * 0 means Datagram is not supported
   */
  [[nodiscard]] virtual uint16_t getDatagramSizeLimit() const = 0;

  /**
   * Writes a Datagram frame. If buf is larger than the size limit returned by
   * getDatagramSizeLimit(), or if the write buffer is full, buf will simply be
   * dropped, and a LocalErrorCode will be returned to caller.
   */
  virtual WriteResult writeDatagram(BufPtr buf) = 0;

  /**
   * Returns the currently available received Datagrams.
   * Returns all datagrams if atMost is 0.
   */
  virtual quic::Expected<std::vector<ReadDatagram>, LocalErrorCode>
  readDatagrams(size_t atMost = 0) = 0;

  /**
   * Returns the currently available received Datagram IOBufs.
   * Returns all datagrams if atMost is 0.
   */
  virtual quic::Expected<std::vector<BufPtr>, LocalErrorCode> readDatagramBufs(
      size_t atMost = 0) = 0;

  /**
   * Sets whether retransmissions are disabled for a specific stream.
   *
   * @param id The stream ID
   * @param disabled If true, retransmissions are disabled for this stream
   */
  virtual quic::Expected<void, LocalErrorCode> setStreamRetransmissionDisabled(
      StreamId id,
      bool disabled) noexcept = 0;

  using Observer = SocketObserverContainer::Observer;
  using ManagedObserver = SocketObserverContainer::ManagedObserver;

  /**
   * Adds an observer.
   *
   * If the observer is already added, this is a no-op.
   *
   * @param observer     Observer to add.
   * @return             Whether the observer was added (fails if no list).
   */
  bool addObserver(Observer* observer) {
    if (auto list = getSocketObserverContainer()) {
      list->addObserver(observer);
      return true;
    }
    return false;
  }

  /**
   * Adds an observer.
   *
   * If the observer is already added, this is a no-op.
   *
   * @param observer     Observer to add.
   * @return             Whether the observer was added (fails if no list).
   */
  bool addObserver(std::shared_ptr<Observer> observer) {
    if (auto list = getSocketObserverContainer()) {
      list->addObserver(std::move(observer));
      return true;
    }
    return false;
  }

  /**
   * Removes an observer.
   *
   * @param observer     Observer to remove.
   * @return             Whether the observer was found and removed.
   */
  bool removeObserver(Observer* observer) {
    if (auto list = getSocketObserverContainer()) {
      return list->removeObserver(observer);
    }
    return false;
  }

  /**
   * Removes an observer.
   *
   * @param observer     Observer to remove.
   * @return             Whether the observer was found and removed.
   */
  bool removeObserver(std::shared_ptr<Observer> observer) {
    if (auto list = getSocketObserverContainer()) {
      return list->removeObserver(std::move(observer));
    }
    return false;
  }

  /**
   * Get number of observers.
   *
   * @return             Number of observers.
   */
  [[nodiscard]] size_t numObservers() const {
    if (auto list = getSocketObserverContainer()) {
      return list->numObservers();
    }
    return 0;
  }

  /**
   * Returns list of attached observers.
   *
   * @return             List of observers.
   */
  std::vector<Observer*> getObservers() {
    if (auto list = getSocketObserverContainer()) {
      return list->getObservers();
    }
    return {};
  }

  /**
   * Returns list of attached observers that are of type T.
   *
   * @return             Attached observers of type T.
   */
  template <typename T = Observer>
  std::vector<T*> findObservers() {
    if (auto list = getSocketObserverContainer()) {
      return list->findObservers<T>();
    }
    return {};
  }
};
} // namespace quic
