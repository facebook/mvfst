/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Expected.h>
#include <folly/io/async/AsyncUDPSocket.h>

#include <quic/QuicException.h>
#include <quic/api/QuicPacketScheduler.h>
#include <quic/api/QuicSocket.h>
#include <quic/state/StateData.h>

// Function to schedule writing data to socket. Return number of packets
// successfully scheduled
namespace quic {

using HeaderBuilder = std::function<PacketHeader(
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    PacketNum packetNum,
    QuicVersion version,
    Buf token)>;

using WritableBytesFunc =
    std::function<uint64_t(const QuicConnectionStateBase& conn)>;

/**
 * Attempts to write data from all frames in the QUIC connection into the UDP
 * socket supplied with the aead and the headerCipher.
 */
uint64_t writeQuicDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit);

/**
 * Writes only the crypto and ack frames to the socket.
 *
 * return the number of packets written to socket.
 */
uint64_t writeCryptoAndAckDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types packetType,
    Aead& cleartextCipher,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    Buf token = nullptr);

/**
 * Writes out all the data streams without writing out crypto streams.
 * This is useful when the crypto stream still needs to be sent in separate
 * packets and cannot use the encryption of the data key.
 */
uint64_t writeQuicDataExceptCryptoStreamToSocket(
    folly::AsyncUDPSocket& socket,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit);

/**
 * Writes frame data including zero rtt data to the socket with the supplied
 * zero rtt cipher.
 */
uint64_t writeZeroRttDataToSocket(
    folly::AsyncUDPSocket& socket,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit);

/**
 * Whether we should and can write data.
 *
 * TODO: We should probably split "should" and "can" into two APIs.
 */
WriteDataReason shouldWriteData(const QuicConnectionStateBase& conn);
bool hasAckDataToWrite(const QuicConnectionStateBase& conn);
WriteDataReason hasNonAckDataToWrite(const QuicConnectionStateBase& conn);

/**
 * Invoked when the written stream data was new stream data.
 */
void handleNewStreamDataWritten(
    QuicConnectionStateBase& conn,
    QuicStreamLike& stream,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace);

/**
 * Invoked when the stream data written was retransmitted data.
 */
void handleRetransmissionWritten(
    QuicConnectionStateBase& conn,
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum);

/**
 * Update the connection and stream state after stream data is written and deal
 * with new data, as well as retranmissions. Returns true if the data sent is
 * new data.
 */
bool handleStreamWritten(
    QuicConnectionStateBase& conn,
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace);

/**
 * Update the connection state after sending a new packet.
 */
void updateConnection(
    QuicConnectionStateBase& conn,
    folly::Optional<PacketEvent> packetEvent,
    RegularQuicWritePacket packet,
    TimePoint time,
    uint32_t encodedSize);

uint64_t congestionControlWritableBytes(const QuicConnectionStateBase& conn);

uint64_t unlimitedWritableBytes(const QuicConnectionStateBase&);

void writeCloseCommon(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    PacketHeader&& header,
    folly::Optional<std::pair<QuicErrorCode, std::string>> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher);

/**
 * Writes a LongHeader packet with a close frame.
 * The close frame type written depends on the type of error in closeDetails.
 */
void writeLongClose(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types headerType,
    folly::Optional<std::pair<QuicErrorCode, std::string>> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion);

/**
 * Write a short header packet with a close frame.
 * The close frame type written depends on the type of error in closeDetails.
 */
void writeShortClose(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& connId,
    folly::Optional<std::pair<QuicErrorCode, std::string>> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher);

/**
 * Encrypts the packet header for the header type.
 * This will overwrite the header with the encrypted header form. It will verify
 * whether or not there are enough bytes to sample for the header encryption
 * from the encryptedBody, and if there is not enough, it will throw an
 * exception.
 */
void encryptPacketHeader(
    HeaderForm headerType,
    folly::IOBuf& header,
    folly::IOBuf& encryptedBody,
    const PacketNumberCipher& cipher);

/**
 * Writes the connections data to the socket using the header
 * builder as well as the scheduler. This will write the amount of
 * data allowed by the writableBytesFunc and will only write a maximum
 * number of packetLimit packets at each invocation.
 */
uint64_t writeConnectionDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const HeaderBuilder& builder,
    PacketNumberSpace pnSpace,
    QuicPacketScheduler& scheduler,
    const WritableBytesFunc& writableBytesFunc,
    uint64_t packetLimit,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    Buf token = nullptr);

uint64_t writeProbingDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const HeaderBuilder& builder,
    PacketNumberSpace pnSpace,
    FrameScheduler scheduler,
    uint8_t probesToSend,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version);

HeaderBuilder LongHeaderBuilder(LongHeader::Types packetType);
HeaderBuilder ShortHeaderBuilder();

} // namespace quic
