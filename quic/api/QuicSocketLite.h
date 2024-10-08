/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/MaybeManagedPtr.h>
#include <folly/io/async/AsyncTransportCertificate.h>
#include <quic/QuicException.h>
#include <quic/codec/Types.h>
#include <quic/state/StateData.h>

namespace quic {

class QuicSocketLite {
 public:
  /**
   * Callback for connection set up events.
   */
  class ConnectionSetupCallback {
   public:
    virtual ~ConnectionSetupCallback() = default;

    /**
     * Called after the transport successfully processes the received packet.
     */
    virtual void onFirstPeerPacketProcessed() noexcept {}

    /**
     * Invoked when the connection setup fails.
     */
    virtual void onConnectionSetupError(QuicError code) noexcept = 0;

    /**
     * Called when the transport is ready to send/receive data.
     * This can be potentially triggered immediately when using 0-RTT.
     */
    virtual void onTransportReady() noexcept {}

    /**
     * Client only.
     * Called when the transport becomes replay safe - both crypto keys derived.
     * Called after onTransportReady() and in case of 0-RTT, unlike
     * onTransportReady(), signifies full crypto handshake finished.
     */
    virtual void onReplaySafe() noexcept {}

    /**
     * Essentially Server only as clients have onReplaySafe.
     * Called after onTransportReady() and in case of 0-RTT, unlike
     * onTransportReady(), signifies full crypto handshake finished.
     */
    virtual void onFullHandshakeDone() noexcept {}
  };

  /**
   * Callback for connection level events once connection is set up.
   * The name is temporary until we phase out the old monolithic callback.
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
     * Invoked when the peer creates a new bidirectional stream group.
     */
    virtual void onNewBidirectionalStreamGroup(StreamGroupId) noexcept {}

    /**
     * Invoked when the peer creates a new bidirectional stream in a specific
     * group.
     */
    virtual void onNewBidirectionalStreamInGroup(
        StreamId,
        StreamGroupId) noexcept {}

    /**
     * Invoked when the peer creates a new unidirectional stream.  The most
     * common flow would be to set the ReadCallback from here
     */
    virtual void onNewUnidirectionalStream(StreamId id) noexcept = 0;

    /**
     * Invoked when the peer creates a new unidirectional stream group.
     */
    virtual void onNewUnidirectionalStreamGroup(StreamGroupId) noexcept {}

    /**
     * Invoked when the peer creates a new unidirectional stream in a specific
     * group.
     */
    virtual void onNewUnidirectionalStreamInGroup(
        StreamId,
        StreamGroupId) noexcept {}

    /**
     * Invoked when a given stream has been closed and its state is about to
     * be reaped by the transport. This is the last chance to do any final
     * state querying operations on the stream.
     */
    virtual void onStreamPreReaped(StreamId) noexcept {}

    /**
     * Invoked when a stream receives a StopSending frame from a peer.
     * The application should reset the stream as part of this callback.
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
    virtual void onConnectionError(QuicError code) noexcept = 0;

    /**
     * Invoked on transport closure. No callbacks will be delivered after this.
     * onConnectionEnd() and onConnectionError(QuicError code) will be
     * deprecated in favor of this new combined callback soon.
     */
    virtual void onConnectionEnd(QuicError /* error */) noexcept {}

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

    // Number of packets that contain STREAM frame for this stream and are
    // declared to be lost
    uint64_t streamLossCount{0};

    // Total number of 'new' stream bytes sent on this stream.
    // Does not include retransmissions of stream bytes.
    Optional<uint64_t> streamBytesSent{0};

    // Total number of stream bytes received on this stream.
    Optional<uint64_t> streamBytesReceived{0};

    // Stream read error (if one occured)
    Optional<QuicErrorCode> streamReadError;
    // Stream write error (if one occured)
    Optional<QuicErrorCode> streamWriteError;
  };

  /**
   * Determine if transport is open and ready to read or write.
   *
   * return true iff the transport is open and ready, false otherwise.
   */
  virtual bool good() const = 0;

  /**
   * Determine if an error has occurred with this transport.
   */
  virtual bool error() const = 0;

  /**
   * Sets connection setup callback. This callback must be set before using the
   * socket.
   */
  virtual void setConnectionSetupCallback(
      folly::MaybeManagedPtr<ConnectionSetupCallback> callback) = 0;

  /**
   * Sets connection streams callback. This callback must be set after
   * connection set up is finished and is ready for streams processing.
   */
  virtual void setConnectionCallback(
      folly::MaybeManagedPtr<ConnectionCallback> callback) = 0;

  /**
   * Get information on the state of the quic connection. Should only be used
   * for logging.
   */
  virtual const QuicConnectionStateBase* getState() const = 0;

  /**
   * Get internal transport info similar to TCP information.
   * Returns LocalErrorCode::STREAM_NOT_EXISTS if the stream is not found
   */
  virtual folly::Expected<StreamTransportInfo, LocalErrorCode>
  getStreamTransportInfo(StreamId id) const = 0;

  /**
   * Get the peer socket address
   */
  virtual const folly::SocketAddress& getPeerAddress() const = 0;

  /**
   * Get the cert presented by peer
   */
  FOLLY_NODISCARD virtual const std::shared_ptr<
      const folly::AsyncTransportCertificate>
  getPeerCertificate() const {
    return nullptr;
  }

  /**
   * Get the cert presented by self
   */
  FOLLY_NODISCARD virtual const std::shared_ptr<
      const folly::AsyncTransportCertificate>
  getSelfCertificate() const {
    return nullptr;
  }

  /**
   * Derive exported key material (RFC5705) from the transport's TLS layer, if
   * the transport is capable.
   */
  virtual Optional<std::vector<uint8_t>> getExportedKeyingMaterial(
      const std::string& label,
      const Optional<folly::ByteRange>& context,
      uint16_t keyLength) const = 0;

  virtual ~QuicSocketLite() = default;
};

} // namespace quic
