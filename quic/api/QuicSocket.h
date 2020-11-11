/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Expected.h>
#include <folly/Optional.h>
#include <folly/io/IOBuf.h>
#include <folly/io/async/AsyncTransportCertificate.h>
#include <quic/QuicConstants.h>
#include <quic/api/Observer.h>
#include <quic/codec/Types.h>
#include <quic/common/SmallVec.h>
#include <quic/state/StateData.h>

#include <chrono>
#include "folly/Portability.h"

namespace folly {
class EventBase;
}

namespace quic {

class QuicSocket {
 public:
  /**
   * Callback for connection level events.  This callback must be set at all
   * times.
   */
  class ConnectionCallback {
   public:
    virtual ~ConnectionCallback() = default;

    /**
     * Invoked when stream id's flow control state changes.  This is an edge
     * triggred API and will be only invoked at the point that the flow control
     * changes.
     */
    virtual void onFlowControlUpdate(StreamId /*id*/) noexcept {}

    /**
     * Invoked when the peer creates a new bidirectional stream.  The most
     * common flow would be to set the ReadCallback from here
     */
    virtual void onNewBidirectionalStream(StreamId id) noexcept = 0;

    /**
     * Invoked when the peer creates a new unidirectional stream.  The most
     * common flow would be to set the ReadCallback from here
     */
    virtual void onNewUnidirectionalStream(StreamId id) noexcept = 0;

    /**
     * Invokved when a stream receives a StopSending frame from a peer.
     */
    virtual void onStopSending(
        StreamId id,
        ApplicationErrorCode error) noexcept = 0;

    /**
     * Invoked when the transport initiates close. No callbacks will
     * be delivered after this
     */
    virtual void onConnectionEnd() noexcept = 0;

    /**
     * Invoked when the connection closed in error
     */
    virtual void onConnectionError(
        std::pair<QuicErrorCode, std::string> code) noexcept = 0;

    /**
     * Client only.
     * Called when the transport becomes replay safe.
     */
    virtual void onReplaySafe() noexcept {}

    /**
     * Called when the transport is ready to send/receive data.
     */
    virtual void onTransportReady() noexcept {}

    /**
     * Called after the transport successfully processes the received packet.
     */
    virtual void onFirstPeerPacketProcessed() noexcept {}

    /**
     * Called when more bidirectional streams become available for creation
     * (max local bidirectional stream ID was increased).
     */
    virtual void onBidirectionalStreamsAvailable(
        uint64_t /*numStreamsAvailable*/) noexcept {}

    /**
     * Called when more unidirectional streams become available for creation
     * (max local unidirectional stream ID was increased).
     */
    virtual void onUnidirectionalStreamsAvailable(
        uint64_t /*numStreamsAvailable*/) noexcept {}

    /**
     * Invoked when transport is detected to be app rate limited.
     */
    virtual void onAppRateLimited() noexcept {}

    /**
     * Invoked when we receive a KnobFrame from the peer
     */
    virtual void
    onKnob(uint64_t /*knobSpace*/, uint64_t /*knobId*/, Buf /*knobBlob*/) {}
  };

  /**
   * Information about the transport, similar to what TCP has.
   */
  struct TransportInfo {
    std::chrono::microseconds srtt{0us};
    std::chrono::microseconds rttvar{0us};
    std::chrono::microseconds lrtt{0us};
    std::chrono::microseconds mrtt{0us};
    uint64_t mss{kDefaultUDPSendPacketLen};
    CongestionControlType congestionControlType{CongestionControlType::None};
    uint64_t writableBytes{0};
    uint64_t congestionWindow{0};
    uint64_t pacingBurstSize{0};
    std::chrono::microseconds pacingInterval{0us};
    uint32_t packetsRetransmitted{0};
    uint32_t packetsSpuriouslyLost{0};
    uint32_t timeoutBasedLoss{0};
    std::chrono::microseconds pto{0us};
    uint64_t bytesSent{0};
    uint64_t bytesAcked{0};
    uint64_t bytesRecvd{0};
    uint64_t totalBytesRetransmitted{0};
    uint32_t ptoCount{0};
    uint32_t totalPTOCount{0};
    folly::Optional<PacketNum> largestPacketAckedByPeer;
    folly::Optional<PacketNum> largestPacketSent;
  };

  /**
   * Information about the stream level transport info. Specific to QUIC.
   */
  struct StreamTransportInfo {
    // Total time the stream has spent in head-of-line blocked state,
    // in microseconds
    std::chrono::microseconds totalHeadOfLineBlockedTime{0us};

    // How many times the stream has entered the "head-of-line blocked" state
    uint32_t holbCount{0};

    // Is the stream head-of-line blocked?
    bool isHolb{false};

    // Number of packets transmitted that carry new STREAM frame for this stream
    uint64_t numPacketsTxWithNewData{0};
  };

  /**
   * Sets connection callback, must be set BEFORE using the socket.
   */
  virtual void setConnectionCallback(ConnectionCallback* callback) = 0;

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
      folly::Function<
          bool(const folly::Optional<std::string>& alpn, const Buf& appParams)
              const> validator,
      folly::Function<Buf()> getter) = 0;

  virtual ~QuicSocket() = default;

  /**
   * ===== Generic Socket Methods =====
   */

  /**
   * Get the QUIC Client Connection ID
   */
  virtual folly::Optional<ConnectionId> getClientConnectionId() const = 0;

  /**
   * Get the QUIC Server Connection ID
   */
  virtual folly::Optional<ConnectionId> getServerConnectionId() const = 0;

  /**
   * Get the original Quic Server Connection ID chosen by client
   */
  FOLLY_NODISCARD virtual folly::Optional<ConnectionId>
  getClientChosenDestConnectionId() const = 0;

  /**
   * Get the peer socket address
   */
  virtual const folly::SocketAddress& getPeerAddress() const = 0;

  /**
   * Get the original peer socket address
   */
  virtual const folly::SocketAddress& getOriginalPeerAddress() const = 0;

  /**
   * Get the local socket address
   */
  virtual const folly::SocketAddress& getLocalAddress() const = 0;

  /**
   * Get the cert presented by peer
   */
  FOLLY_NODISCARD virtual const std::shared_ptr<
      const folly::AsyncTransportCertificate>
  getPeerCertificate() const {
    return nullptr;
  }

  /**
   * Determine if transport is open and ready to read or write.
   *
   * return true iff the transport is open and ready, false otherwise.
   */
  virtual bool good() const = 0;

  virtual bool replaySafe() const = 0;

  /**
   * Determine if an error has occurred with this transport.
   */
  virtual bool error() const = 0;

  /**
   * Close this socket with a drain period. If closing with an error, it may be
   * specified.
   */
  virtual void close(
      folly::Optional<std::pair<QuicErrorCode, std::string>> errorCode) = 0;

  /**
   * Close this socket gracefully, by waiting for all the streams to be idle
   * first.
   */
  virtual void closeGracefully() = 0;

  /**
   * Close this socket without a drain period. If closing with an error, it may
   * be specified.
   */
  virtual void closeNow(
      folly::Optional<std::pair<QuicErrorCode, std::string>> errorCode) = 0;

  /**
   * Returns the event base associated with this socket
   */
  virtual folly::EventBase* getEventBase() const = 0;

  /**
   * Returns the current offset already read or written by the application on
   * the given stream.
   */
  virtual folly::Expected<size_t, LocalErrorCode> getStreamReadOffset(
      StreamId id) const = 0;
  virtual folly::Expected<size_t, LocalErrorCode> getStreamWriteOffset(
      StreamId id) const = 0;
  /**
   * Returns the amount of data buffered by the transport waiting to be written
   */
  virtual folly::Expected<size_t, LocalErrorCode> getStreamWriteBufferedBytes(
      StreamId id) const = 0;

  /**
   * Get internal transport info similar to TCP information.
   */
  virtual TransportInfo getTransportInfo() const = 0;

  /**
   * Get internal transport info similar to TCP information.
   * Returns LocalErrorCode::STREAM_NOT_EXISTS if the stream is not found
   */
  virtual folly::Expected<StreamTransportInfo, LocalErrorCode>
  getStreamTransportInfo(StreamId id) const = 0;

  /**
   * Get the negotiated ALPN. If called before the transport is ready
   * returns folly::none
   */
  virtual folly::Optional<std::string> getAppProtocol() const = 0;

  /**
   * Sets the size of the given stream's receive window, or the connection
   * receive window if stream id is 0.  If the window size increases, a
   * window update will be sent to the peer.  If it decreases, the transport
   * will delay future window updates until the sender's available window is
   * <= recvWindowSize.
   */
  virtual void setReceiveWindow(StreamId id, size_t recvWindowSize) = 0;

  /**
   * Set the size of the transport send buffer for the given stream.
   * The maximum total amount of buffer space is the sum of maxUnacked and
   * maxUnsent.  Bytes passed to writeChain count against unsent until the
   * transport flushes them to the wire, after which they count against unacked.
   */
  virtual void
  setSendBuffer(StreamId id, size_t maxUnacked, size_t maxUnsent) = 0;

  /**
   * Return the amount of transport buffer space available for writing
   */
  virtual uint64_t getConnectionBufferAvailable() const = 0;

  /**
   * Application can invoke this function to signal the transport to
   * initiate migration.
   * @param socket The new socket that should be used by the transport.
   * If this is null then do not replace the underlying socket.
   */
  virtual void onNetworkSwitch(std::unique_ptr<folly::AsyncUDPSocket>) {}

  /**
   * Get the flow control settings for the given stream (or connection flow
   * control by passing id=0).  Settings include send and receive window
   * capacity and available.
   */
  struct FlowControlState {
    // Number of bytes the peer has allowed me to send.
    uint64_t sendWindowAvailable;
    // The max offset provided by the peer.
    uint64_t sendWindowMaxOffset;
    // Number of bytes I have allowed the peer to send.
    uint64_t receiveWindowAvailable;
    // The max offset I have provided to the peer.
    uint64_t receiveWindowMaxOffset;

    FlowControlState(
        uint64_t sendWindowAvailableIn,
        uint64_t sendWindowMaxOffsetIn,
        uint64_t receiveWindowAvailableIn,
        uint64_t receiveWindowMaxOffsetIn)
        : sendWindowAvailable(sendWindowAvailableIn),
          sendWindowMaxOffset(sendWindowMaxOffsetIn),
          receiveWindowAvailable(receiveWindowAvailableIn),
          receiveWindowMaxOffset(receiveWindowMaxOffsetIn) {}
  };

  /**
   * Returns the current flow control windows for the connection.
   * Use getStreamFlowControl for stream flow control window.
   */
  virtual folly::Expected<FlowControlState, LocalErrorCode>
  getConnectionFlowControl() const = 0;

  /**
   * Returns the current flow control windows for the stream, id != 0.
   * Use getConnectionFlowControl for connection flow control window.
   */
  virtual folly::Expected<FlowControlState, LocalErrorCode>
  getStreamFlowControl(StreamId id) const = 0;

  /**
   * Sets the flow control window for the connection.
   * Use setStreamFlowControlWindow for per Stream flow control.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode>
  setConnectionFlowControlWindow(uint64_t windowSize) = 0;

  /**
   * Sets the flow control window for the stream.
   * Use setConnectionFlowControlWindow for connection flow control.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode>
  setStreamFlowControlWindow(StreamId id, uint64_t windowSize) = 0;

  /**
   * Settings for the transport. This takes effect only before the transport
   * is connected.
   */
  virtual void setTransportSettings(TransportSettings transportSettings) = 0;

  virtual const TransportSettings& getTransportSettings() const = 0;

  /**
   * Set a "knob". This will emit a knob frame to the peer, which the peer
   * application can act on by e.g. changing transport settings during the
   * connection.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode>
  setKnob(uint64_t knobSpace, uint64_t knobId, Buf knobBlob) = 0;

  /**
   * Can Knob Frames be exchanged with the peer on this connection?
   */
  FOLLY_NODISCARD virtual bool isKnobSupported() const = 0;

  /**
   * Is partial reliability supported.
   */
  virtual bool isPartiallyReliableTransport() const = 0;

  /**
   * Set stream priority.
   * level: can only be in [0, 7].
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode>
  setStreamPriority(StreamId id, PriorityLevel level, bool incremental) = 0;

  /**
   * ===== Read API ====
   */

  /**
   * Callback class for receiving data on a stream
   */
  class ReadCallback {
   public:
    virtual ~ReadCallback() = default;

    /**
     * Called from the transport layer when there is data, EOF or an error
     * available to read on the given stream ID
     */
    virtual void readAvailable(StreamId id) noexcept = 0;

    /**
     * Called from the transport layer when there is an error on the stream.
     */
    virtual void readError(
        StreamId id,
        std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>
            error) noexcept = 0;
  };

  /**
   * Set the read callback for the given stream.  Note that read callback is
   * expected to be set all the time. Removing read callback indicates that
   * stream is no longer intended to be read again. This will issue a
   * StopSending if cb is being set to nullptr after previously being not
   * nullptr. The err parameter is used to control the error sent in the
   * StopSending. By default when cb is nullptr this function will cause the
   * transport to send a StopSending frame with
   * GenericApplicationErrorCode::NO_ERROR. If err is specified to be
   * folly::none, no StopSending will be sent.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode> setReadCallback(
      StreamId id,
      ReadCallback* cb,
      folly::Optional<ApplicationErrorCode> err =
          GenericApplicationErrorCode::NO_ERROR) = 0;

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
   * Invoke onCanceled on all the delivery callbacks registered for streamId.
   */
  virtual void cancelDeliveryCallbacksForStream(StreamId streamId) = 0;

  /**
   * Invoke onCanceled on all the delivery callbacks registered for streamId for
   * offsets lower than the offset provided.
   */
  virtual void cancelDeliveryCallbacksForStream(
      StreamId streamId,
      uint64_t offset) = 0;

  /**
   * Pause/Resume read callback being triggered when data is available.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode> pauseRead(
      StreamId id) = 0;
  virtual folly::Expected<folly::Unit, LocalErrorCode> resumeRead(
      StreamId id) = 0;

  /**
   * Initiates sending of a StopSending frame for a given stream to the peer.
   * This is called a "solicited reset". On receipt of the StopSending frame
   * the peer should, but may not, send a ResetStream frame for the requested
   * stream. A caller can use this function when they are no longer processing
   * received data on the stream.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode> stopSending(
      StreamId id,
      ApplicationErrorCode error) = 0;

  /**
   * Read from the given stream, up to maxLen bytes.  If maxLen is 0, transport
   * will return all available bytes.
   *
   * The return value is Expected.  If the value hasError(), then a read error
   * occured and it can be obtained with error().  If the value hasValue(), then
   * value() returns a pair of the data (if any) and the EOF marker.
   *
   * Calling read() when there is no data/eof to deliver will return an
   * EAGAIN-like error code.
   */
  virtual folly::Expected<std::pair<Buf, bool>, LocalErrorCode> read(
      StreamId id,
      size_t maxLen) = 0;

  /**
   * ===== Peek/Consume API =====
   */

  /**
   * Usage:
   * class Application {
   *   void onNewBidirectionalStream(StreamId id) {
   *     socket_->setPeekCallback(id, this);
   *   }
   *
   *   virtual void onDataAvailable(
   *       StreamId id,
   *       const folly::Range<PeekIterator>& peekData) noexcept override
   *   {
   *     auto amount = tryInterpret(peekData);
   *     if (amount) {
   *       socket_->consume(id, amount);
   *     }
   *   }
   * };
   */

  using PeekIterator = std::deque<StreamBuffer>::const_iterator;
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
  };
  virtual folly::Expected<folly::Unit, LocalErrorCode> setPeekCallback(
      StreamId id,
      PeekCallback* cb) = 0;

  /**
   * Pause/Resume peek callback being triggered when data is available.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode> pausePeek(
      StreamId id) = 0;
  virtual folly::Expected<folly::Unit, LocalErrorCode> resumePeek(
      StreamId id) = 0;

  /**
   * Peek at the given stream.
   *
   * The return value is Expected.  If the value hasError(), then a read error
   * occured and it can be obtained with error().  If the value hasValue(),
   * indicates that peekCallback has been called.
   *
   * The range that is passed to callback is only valid until callback returns,
   * If caller need to preserve data that range points to - that data has to
   * be copied.
   *
   * Calling peek() when there is no data/eof to deliver will return an
   * EAGAIN-like error code.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode> peek(
      StreamId id,
      const folly::Function<void(StreamId id, const folly::Range<PeekIterator>&)
                                const>& peekCallback) = 0;

  /**
   * Consumes data on the given stream, starting from currentReadOffset
   *
   * The return value is Expected.  If the value hasError(), then a read error
   * occured and it can be obtained with error().
   *
   * @offset - represents start of consumed range.
   * Current implementation returns error and currentReadOffset if offset !=
   * currentReadOffset
   *
   * Calling consume() when there is no data/eof to deliver
   * will return an EAGAIN-like error code.
   *
   */
  virtual folly::Expected<
      folly::Unit,
      std::pair<LocalErrorCode, folly::Optional<uint64_t>>>
  consume(StreamId id, uint64_t offset, size_t amount) = 0;

  /**
   * Equivalent of calling consume(id, stream->currentReadOffset, amount);
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode> consume(
      StreamId id,
      size_t amount) = 0;

  /**
   * ===== Expire/reject API =====
   *
   * Sender can "expire" stream data by advancing receiver's minimum
   * retransmittable offset, effectively discarding some of the previously
   * sent (or planned to be sent) data.
   * Discarded data may or may not have already arrived on the receiver end.
   *
   * Received can "reject" stream data by advancing sender's minimum
   * retransmittable offset, effectively discarding some of the previously
   * sent (or planned to be sent) data.
   * Rejected data may or may not have already arrived on the receiver end.
   */

  class DataExpiredCallback {
   public:
    virtual ~DataExpiredCallback() = default;

    /**
     * Called from the transport layer when sender informes us that data is
     * expired on a given stream.
     */
    virtual void onDataExpired(StreamId id, uint64_t newOffset) noexcept = 0;
  };

  virtual folly::Expected<folly::Unit, LocalErrorCode> setDataExpiredCallback(
      StreamId id,
      DataExpiredCallback* cb) = 0;

  /**
   * Expire data.
   *
   * The return value is Expected.  If the value hasError(), then an error
   * occured and it can be obtained with error().
   */
  virtual folly::Expected<folly::Optional<uint64_t>, LocalErrorCode>
  sendDataExpired(StreamId id, uint64_t offset) = 0;

  class DataRejectedCallback {
   public:
    virtual ~DataRejectedCallback() = default;

    /**
     * Called from the transport layer when receiver informes us that data is
     * not needed anymore on a given stream.
     */
    virtual void onDataRejected(StreamId id, uint64_t newOffset) noexcept = 0;
  };

  virtual folly::Expected<folly::Unit, LocalErrorCode> setDataRejectedCallback(
      StreamId id,
      DataRejectedCallback* cb) = 0;

  /**
   * Reject data.
   *
   * The return value is Expected.  If the value hasError(), then an error
   * occured and it can be obtained with error().
   */
  virtual folly::Expected<folly::Optional<uint64_t>, LocalErrorCode>
  sendDataRejected(StreamId id, uint64_t offset) = 0;

  /**
   * ===== Write API =====
   */

  /**
   * Creates a bidirectional stream.  This assigns a stream ID but does not
   * send anything to the peer.
   *
   * If replaySafe is false, the transport will buffer (up to the send buffer
   * limits) any writes on this stream until the transport is replay safe.
   */
  virtual folly::Expected<StreamId, LocalErrorCode> createBidirectionalStream(
      bool replaySafe = true) = 0;

  /**
   * Creates a unidirectional stream.  This assigns a stream ID but does not
   * send anything to the peer.
   *
   * If replaySafe is false, the transport will buffer (up to the send buffer
   * limits) any writes on this stream until the transport is replay safe.
   */
  virtual folly::Expected<StreamId, LocalErrorCode> createUnidirectionalStream(
      bool replaySafe = true) = 0;

  /**
   * Returns the number of bidirectional streams that can be opened.
   */
  virtual uint64_t getNumOpenableBidirectionalStreams() const = 0;

  /**
   * Returns the number of unidirectional streams that can be opened.
   */
  virtual uint64_t getNumOpenableUnidirectionalStreams() const = 0;

  /**
   * Returns whether a stream ID represents a client-initiated stream.
   */
  virtual bool isClientStream(StreamId stream) noexcept = 0;

  /**
   * Returns whether a stream ID represents a server-initiated stream.
   */
  virtual bool isServerStream(StreamId stream) noexcept = 0;

  /**
   * Returns whether a stream ID represents a unidirectional stream.
   */
  virtual bool isUnidirectionalStream(StreamId stream) noexcept = 0;

  /**
   * Returns whether a stream ID represents a bidirectional stream.
   */
  virtual bool isBidirectionalStream(StreamId stream) noexcept = 0;

  /**
   * Callback class for receiving write readiness notifications
   */
  class WriteCallback {
   public:
    virtual ~WriteCallback() = default;

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
     * notifyPendingWriteOnStream has been called
     */
    virtual void onStreamWriteError(
        StreamId /* id */,
        std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>
        /* error */) noexcept {}

    /**
     * Invoked when a connection is being torn down after
     * notifyPendingWriteOnConnection has been called
     */
    virtual void onConnectionWriteError(
        std::pair<QuicErrorCode, folly::Optional<folly::StringPiece>>
        /* error */) noexcept {}
  };

  /**
   * Inform the transport that there is data to write on this connection
   * An app shouldn't mix connection and stream calls to this API
   * Use this if the app wants to do prioritization.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode>
  notifyPendingWriteOnConnection(WriteCallback* wcb) = 0;

  /**
   * Inform the transport that there is data to write on a given stream.
   * An app shouldn't mix connection and stream calls to this API
   * Use the Connection call if the app wants to do prioritization.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode>
  notifyPendingWriteOnStream(StreamId id, WriteCallback* wcb) = 0;

  virtual folly::Expected<folly::Unit, LocalErrorCode>
      unregisterStreamWriteCallback(StreamId) = 0;

  /**
   * Structure used to communicate TX and ACK/Delivery notifications.
   */
  struct ByteEvent {
    enum class Type { ACK = 1, TX = 2 };
    static constexpr std::array<Type, 2> kByteEventTypes = {Type::ACK,
                                                            Type::TX};

    StreamId id{0};
    uint64_t offset{0};
    Type type;

    // sRTT at time of event
    // TODO(bschlinker): Deprecate, caller can fetch transport state if desired.
    std::chrono::microseconds srtt{0us};
  };

  /**
   * Structure used to communicate cancellation of a ByteEvent.
   *
   * According to Dictionary.com, cancellation is more frequent in American
   * English than cancelation. Yet in American English, the preferred style is
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
     * Invoked when the byte event has occurred.
     */
    virtual void onByteEvent(ByteEvent byteEvent) = 0;

    /**
     * Invoked if byte event is canceled due to reset, shutdown, or other error.
     */
    virtual void onByteEventCanceled(ByteEventCancellation cancellation) = 0;
  };

  /**
   * Callback class for receiving ack notifications
   */
  class DeliveryCallback : public ByteEventCallback {
   public:
    virtual ~DeliveryCallback() = default;

    /**
     * Invoked when the peer has acknowledged the receipt of the specified
     * offset.  rtt is the current RTT estimate for the connection.
     */
    virtual void onDeliveryAck(
        StreamId id,
        uint64_t offset,
        std::chrono::microseconds rtt) = 0;

    /**
     * Invoked on registered delivery callbacks when the bytes will never be
     * delivered (due to a reset or other error).
     */
    virtual void onCanceled(StreamId id, uint64_t offset) = 0;

   private:
    // Temporary shim during transition to ByteEvent
    void onByteEvent(ByteEvent byteEvent) final {
      CHECK_EQ((int)ByteEvent::Type::ACK, (int)byteEvent.type); // sanity
      onDeliveryAck(byteEvent.id, byteEvent.offset, byteEvent.srtt);
    }

    // Temporary shim during transition to ByteEvent
    void onByteEventCanceled(ByteEventCancellation cancellation) final {
      CHECK_EQ((int)ByteEvent::Type::ACK, (int)cancellation.type); // sanity
      onCanceled(cancellation.id, cancellation.offset);
    }
  };

  /**
   * Register a callback to be invoked when the stream offset was transmitted.
   *
   * Currently, an offset is considered "transmitted" if it has been written to
   * to the underlying UDP socket, indicating that it has passed through
   * congestion control and pacing. In the future, this callback may be
   * triggered by socket/NIC software or hardware timestamps.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode> registerTxCallback(
      const StreamId id,
      const uint64_t offset,
      ByteEventCallback* cb) = 0;

  /**
   * Register a byte event to be triggered when specified event type occurs for
   * the specified stream and offset.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode>
  registerByteEventCallback(
      const ByteEvent::Type type,
      const StreamId id,
      const uint64_t offset,
      ByteEventCallback* cb) = 0;

  /**
   * Cancel byte event callbacks for given stream.
   *
   * If an offset is provided, cancels only callbacks with an offset less than
   * or equal to the provided offset, otherwise cancels all callbacks.
   */
  virtual void cancelByteEventCallbacksForStream(
      const StreamId id,
      const folly::Optional<uint64_t>& offset = folly::none) = 0;

  /**
   * Cancel byte event callbacks for given type and stream.
   *
   * If an offset is provided, cancels only callbacks with an offset less than
   * or equal to the provided offset, otherwise cancels all callbacks.
   */
  virtual void cancelByteEventCallbacksForStream(
      const ByteEvent::Type type,
      const StreamId id,
      const folly::Optional<uint64_t>& offset = folly::none) = 0;

  /**
   * Cancel all byte event callbacks of all streams.
   */
  virtual void cancelAllByteEventCallbacks() = 0;

  /**
   * Cancel all byte event callbacks of all streams of the given type.
   */
  virtual void cancelByteEventCallbacks(const ByteEvent::Type type) = 0;

  /**
   * Get the number of pending byte events for the given stream.
   */
  FOLLY_NODISCARD virtual size_t getNumByteEventCallbacksForStream(
      const StreamId streamId) const = 0;

  /**
   * Get the number of pending byte events of specified type for given stream.
   */
  FOLLY_NODISCARD virtual size_t getNumByteEventCallbacksForStream(
      const ByteEvent::Type type,
      const StreamId streamId) const = 0;

  /**
   * Write data/eof to the given stream.
   *
   * cork indicates to the transport that the application expects to write
   * more data soon.  Passing a delivery callback registers a callback from the
   * transport when the peer has acknowledged the receipt of all the data/eof
   * passed to write.
   *
   * An error code is present if there was an error with the write.
   */
  using WriteResult = folly::Expected<folly::Unit, LocalErrorCode>;
  virtual WriteResult writeChain(
      StreamId id,
      Buf data,
      bool eof,
      bool cork,
      DeliveryCallback* cb = nullptr) = 0;

  /**
   * Register a callback to be invoked when the peer has acknowledged the
   * given offset on the given stream.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode> registerDeliveryCallback(
      StreamId id,
      uint64_t offset,
      ByteEventCallback* cb) = 0;

  /**
   * Close the stream for writing.  Equivalent to writeChain(id, nullptr, true).
   */
  virtual folly::Optional<LocalErrorCode> shutdownWrite(StreamId id) = 0;

  /**
   * Cancel the given stream
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode> resetStream(
      StreamId id,
      ApplicationErrorCode error) = 0;

  /**
   * Helper method to check a generic error for an Application error, and reset
   * the stream with the reciprocal error.
   *
   * Returns true if the error was an ApplicationErrorCode, and the stream was
   * reset.
   */
  virtual folly::Expected<folly::Unit, LocalErrorCode>
  maybeResetStreamFromReadError(StreamId id, QuicErrorCode error) = 0;

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
  };

  /**
   * Send a ping to the peer.  When the ping is acknowledged by the peer or
   * times out, the transport will invoke the callback.
   *
   * If 'callback' is nullptr, or pingTimeout is 0, no callback is scheduled.
   */
  virtual void sendPing(
      PingCallback* callback,
      std::chrono::milliseconds pingTimeout) = 0;

  /**
   * Get information on the state of the quic connection. Should only be used
   * for logging.
   */
  virtual const QuicConnectionStateBase* getState() const = 0;

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
  virtual void attachEventBase(folly::EventBase* evb) = 0;

  /**
   * Returns whether or not the eventbase can currently be detached from the
   * socket.
   */
  virtual bool isDetachable() = 0;

  /**
   * Signal the transport that a certain stream is a control stream.
   * A control stream outlives all the other streams in a connection, therefore,
   * if the transport knows about it, can enable some optimizations.
   * Applications should declare all their control streams after either calling
   * createStream() or receiving onNewBidirectionalStream()
   */
  virtual folly::Optional<LocalErrorCode> setControlStream(StreamId id) = 0;

  /**
   * Set congestion control type.
   */
  virtual void setCongestionControl(CongestionControlType type) = 0;

  // Container for lifecycle observers.
  // Avoids heap allocation for up to 2 observers being installed.
  using LifecycleObserverVec = SmallVec<LifecycleObserver*, 2>;

  /**
   * Adds a lifecycle observer.
   *
   * Observers can tie their lifetime to aspects of this socket's lifecycle /
   * lifetime and perform inspection at various states.
   *
   * This enables instrumentation to be added without changing / interfering
   * with how the application uses the socket.
   *
   * @param observer     Observer to add (implements LifecycleObserver).
   */
  virtual void addLifecycleObserver(LifecycleObserver* observer) = 0;

  /**
   * Removes a lifecycle observer.
   *
   * @param observer     Observer to remove.
   * @return             Whether observer found and removed from list.
   */
  virtual bool removeLifecycleObserver(LifecycleObserver* observer) = 0;

  /**
   * Returns installed lifecycle observers.
   *
   * @return             Reference to const vector with installed observers.
   */
  FOLLY_NODISCARD virtual const LifecycleObserverVec& getLifecycleObservers()
      const = 0;

  /**
   * Adds a instrumentation observer.
   *
   * Instrumentation observers get notified of various socket events.
   *
   * @param observer     Observer to add (implements InstrumentationObserver).
   */
  virtual void addInstrumentationObserver(
      InstrumentationObserver* observer) = 0;

  /**
   * Removes a instrumentation observer.
   *
   * @param observer     Observer to remove.
   * @return             Whether observer found and removed from list.
   */
  virtual bool removeInstrumentationObserver(
      InstrumentationObserver* observer) = 0;

  /**
   * Returns installed instrumentation observers.
   *
   * @return             Reference to const vector with installed observers.
   */
  FOLLY_NODISCARD virtual const InstrumentationObserverVec&
  getInstrumentationObservers() const = 0;
};
} // namespace quic
