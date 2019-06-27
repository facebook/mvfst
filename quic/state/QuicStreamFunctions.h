/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
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
 * in WaitingForRstAck or Closed state alraedy
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
 * Get the the minimal write offset that's yet to deliver to peer
 */
uint64_t getStreamNextOffsetToDeliver(const QuicStreamState& stream);

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
 * Cancel the retransmissions of the crypto stream data.
 * TODO: remove this when we can deal with cleartext data after handshake done
 * correctly.
 */
void cancelHandshakeCryptoStreamRetransmissions(QuicCryptoState& cryptoStream);

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

/**
 * Checks if ack frame matches buffer from the retransmit queue.
 *
 * @param stream    The stream.
 * @param ackFrame  Ack frame that allegedly acks the above buffer.
 * @param buf       Buffer from the retransmit queue.
 */
bool ackFrameMatchesRetransmitBuffer(
    const QuicStreamState& stream,
    const WriteStreamFrame& ackFrame,
    const StreamBuffer& buf);
} // namespace quic
