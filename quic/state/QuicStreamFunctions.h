/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/state/StateData.h>
#include <algorithm>

namespace quic {

/**
 * Adds data to the end of the write buffer of the QUIC stream. This
 * data will be written onto the socket.
 *
 * @throws QuicTransportException on error.
 */
void writeDataToQuicStream(QuicStreamState& stream, Buf data, bool eof);

/**
 * Adds data represented in the form of BufferMeta to the end of the Buffer
 * Meta queue of the stream.
 *
 * TODO: move to dsr directory.
 */
void writeBufMetaToQuicStream(
    QuicStreamState& stream,
    const BufferMeta& data,
    bool eof);

/**
 * Adds data to the end of the write buffer of the QUIC crypto stream. This
 * data will be written onto the socket.
 */
void writeDataToQuicStream(QuicCryptoStream& stream, Buf data);

/**
 * Process data received from the network to add it to the QUIC stream.
 * appendDataToReadBuffer handles any reordered or non contiguous data.
 *
 * @throws QuicTransportException on error.
 */
void appendDataToReadBuffer(QuicStreamState& stream, StreamBuffer buffer);

/**
 * Process data received from the network to add it to the crypto stream.
 * appendDataToReadBuffer handles any reordered or non contiguous data.
 *
 * @throws QuicTransportException on error.
 */
void appendDataToReadBuffer(QuicCryptoStream& stream, StreamBuffer buffer);

/**
 * Reads data from the QUIC stream if data exists.
 * Returns a pair of data and whether or not EOF was reached on the stream.
 * amount == 0 reads all the pending data in the stream.
 */
std::pair<Buf, bool> readDataFromQuicStream(
    QuicStreamState& state,
    uint64_t amount = 0);

/**
 * Reads data from the QUIC crypto data if data exists.
 * amount == 0 reads all the pending data in the stream.
 */
Buf readDataFromCryptoStream(QuicCryptoStream& stream, uint64_t amount = 0);

/**
 * Peeks data from the QUIC stream if data exists.
 * Invokes provided callback on the existing data.
 * Does not affect stream state (as opposed to read).
 */
using PeekIterator = std::deque<StreamBuffer>::const_iterator;
void peekDataFromQuicStream(
    QuicStreamState& state,
    const folly::Function<void(StreamId id, const folly::Range<PeekIterator>&)
                              const>& peekCallback);

/**
 * Releases data from QUIC stream.
 * Same as readDataFromQuicStream,
 * releases data instead of returning it.
 */
void consumeDataFromQuicStream(QuicStreamState& stream, uint64_t amount);

bool allBytesTillFinAcked(const QuicStreamState& state);

/**
 * Add a pending reset for stream into conn's pendingEvents if the stream isn't
 * in WaitingForRstAck or Closed state already
 */
void appendPendingStreamReset(
    QuicConnectionStateBase& conn,
    const QuicStreamState& stream,
    ApplicationErrorCode errorCode);

/**
 * Get the largest write offset the stream has seen
 */
uint64_t getLargestWriteOffsetSeen(const QuicStreamState& stream);

/**
 * Get the largest write offset the stream has transmitted / written to socket.
 *
 * If no bytes have been written to the socket yet, returns folly::none.
 */
folly::Optional<uint64_t> getLargestWriteOffsetTxed(
    const QuicStreamState& stream);

/**
 * Get the the highest acked offset (if any) that we can execute delivery
 * callbacks on.
 */
folly::Optional<uint64_t> getLargestDeliverableOffset(
    const QuicStreamState& stream);

/**
 * Get the version associated with the stream's ACK IntervalSet.
 *
 * The version changes every time a new interval is added to the IntervalSet.
 */
uint64_t getAckIntervalSetVersion(const QuicStreamState& stream);

/**
 * Get the cumulative number of packets that contains STREAM frame for this
 * stream. It does not count retransmissions.
 */
uint64_t getNumPacketsTxWithNewData(const QuicStreamState& stream);

/**
 * Common functions for merging data into the read buffer for a Quic stream like
 * object. Callers should provide a connFlowControlVisitor which will be invoked
 * when flow control operations need to be performed.
 */
void appendDataToReadBufferCommon(
    QuicStreamLike& stream,
    StreamBuffer buffer,
    folly::Function<void(uint64_t, uint64_t)>&& connFlowControlVisitor);

/**
 * Common function to read data from the read buffer in order. Returns a pair of
 * the buffer that was read and whether or not the FIN for the stream was read.
 * sinkData == true discards data instead of returning it.
 */
std::pair<Buf, bool> readDataInOrderFromReadBuffer(
    QuicStreamLike& stream,
    uint64_t amount,
    bool sinkData = false);

/**
 * Returns the appropriate crypto stream for the protection type of the packet.
 */
QuicCryptoStream* getCryptoStream(
    QuicCryptoState& cryptoState,
    EncryptionLevel encryptionLevel);

void processCryptoStreamAck(
    QuicCryptoStream& cryptoStream,
    uint64_t offset,
    uint64_t len);

// Drops ingress when sending STOP_SENDING to peer
void processTxStopSending(QuicStreamState& stream);

} // namespace quic
