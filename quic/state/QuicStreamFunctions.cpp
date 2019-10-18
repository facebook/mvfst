/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/state/QuicStreamFunctions.h>
#include <quic/QuicException.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/logging/QuicLogger.h>
#include <quic/state/QuicStreamUtilities.h>

#include <folly/io/Cursor.h>
#include <algorithm>

namespace {
void prependToBuf(quic::Buf& buf, quic::Buf toAppend) {
  if (buf) {
    buf->prependChain(std::move(toAppend));
  } else {
    buf = std::move(toAppend);
  }
}
} // namespace

namespace quic {

void writeDataToQuicStream(QuicStreamState& stream, Buf data, bool eof) {
  uint64_t len = 0;
  if (data) {
    len = data->computeChainDataLength();
  }
  if (len > 0) {
    // We call this before updating the writeBuffer because we only want to
    // write a blocked frame first time the stream becomes blocked
    maybeWriteBlockAfterAPIWrite(stream);
  }
  stream.writeBuffer.append(std::move(data));
  if (eof) {
    auto bufferSize =
        stream.writeBuffer.front() ? stream.writeBuffer.chainLength() : 0;
    stream.finalWriteOffset = stream.currentWriteOffset + bufferSize;
  }
  updateFlowControlOnWriteToStream(stream, len);
  stream.conn.streamManager->updateWritableStreams(stream);
}

void writeDataToQuicStream(QuicCryptoStream& stream, Buf data) {
  stream.writeBuffer.append(std::move(data));
}

void appendDataToReadBufferCommon(
    QuicStreamLike& stream,
    StreamBuffer buffer,
    folly::Function<void(uint64_t, uint64_t)>&& connFlowControlVisitor) {
  auto& readBuffer = stream.readBuffer;
  auto it = readBuffer.begin();

  auto bufferEndOffset = buffer.offset + buffer.data.chainLength();

  folly::Optional<uint64_t> bufferEofOffset;
  if (buffer.eof) {
    bufferEofOffset = bufferEndOffset;
  } else if (buffer.data.chainLength() == 0) {
    VLOG(10) << "Empty stream without EOF";
    return;
  }

  if (stream.finalReadOffset && bufferEofOffset &&
      *stream.finalReadOffset != *bufferEofOffset) {
    throw QuicTransportException(
        "Invalid EOF", TransportErrorCode::FINAL_SIZE_ERROR);
  } else if (bufferEofOffset) {
    // Do some consistency checks on the stream.
    if (stream.maxOffsetObserved > *bufferEofOffset) {
      throw QuicTransportException(
          "EOF in middle of stream", TransportErrorCode::FINAL_SIZE_ERROR);
    }
    stream.finalReadOffset = bufferEofOffset;
  } else if (stream.finalReadOffset) {
    // We did not receive a segment with an EOF set.
    if (buffer.offset + buffer.data.chainLength() > *stream.finalReadOffset) {
      throw QuicTransportException(
          "Invalid data after EOF", TransportErrorCode::FINAL_SIZE_ERROR);
    }
  }
  // Update the flow control information before changing max offset observed on
  // the stream.
  connFlowControlVisitor(stream.maxOffsetObserved, bufferEndOffset);
  stream.maxOffsetObserved =
      std::max(stream.maxOffsetObserved, bufferEndOffset);

  if (buffer.data.chainLength() == 0) {
    // Nothing more to do since we already processed the EOF
    // case.
    return;
  }

  if (buffer.offset < stream.currentReadOffset) {
    // trim the buffer to start from stream read offset.
    buffer.data.trimStartAtMost(stream.currentReadOffset - buffer.offset);
    buffer.offset = stream.currentReadOffset;
    if (buffer.data.chainLength() == 0) {
      return;
    }
  }

  // Nothing in the buffer, just append it.
  if (it == readBuffer.end()) {
    readBuffer.emplace_back(std::move(buffer));
    return;
  }

  // Start overlap will point to the first buffer that overlaps with the
  // current buffer and End overlap will point to the last buffer that overlaps.
  // They must always be set together.
  folly::Optional<std::deque<StreamBuffer>::iterator> startOverlap;
  folly::Optional<std::deque<StreamBuffer>::iterator> endOverlap;

  StreamBuffer* current = &buffer;
  bool currentAlreadyInserted = false;
  bool done = false;
  it = std::lower_bound(
      it,
      readBuffer.end(),
      current->offset,
      [](const StreamBuffer& listValue, uint64_t offset) {
        // First element where the end offset is > start offset of the buffer.
        return (listValue.offset + listValue.data.chainLength()) < offset;
      });

  // The invariant we're trying to maintain here is that individual
  // elements of the readBuffer are assuredly non contiguous sections
  // of the stream.
  for (; it != readBuffer.end() && !done; ++it) {
    auto currentEnd = current->offset + current->data.chainLength();
    auto itEnd = it->offset + it->data.chainLength();
    if (current->offset == it->offset && currentEnd == itEnd) {
      // Exact overlap. Done.
      done = true;
    } else if (current->offset >= it->offset && currentEnd <= itEnd) {
      // Subset overlap
      done = true;
    } else if (
        current->offset <= it->offset && currentEnd >= it->offset &&
        currentEnd <= itEnd) {
      // Left overlap. Done.
      it->data.trimStartAtMost(currentEnd - it->offset);
      if (it->data.chainLength() > 0) {
        current->data.append(it->data.move());
      }
      if (!startOverlap) {
        startOverlap = it;
      }
      endOverlap = it + 1;
      done = true;
    } else if (current->offset < it->offset && currentEnd < it->offset) {
      // Left, no overlap. Done.
      if (!startOverlap) {
        startOverlap = it;
        endOverlap = it;
      }
      done = true;
    } else if (current->offset <= it->offset && currentEnd > it->offset) {
      // Complete overlap. Need to move on.
      if (!startOverlap) {
        startOverlap = it;
      }
      endOverlap = it + 1;
    } else if (
        current->offset >= it->offset && current->offset <= itEnd &&
        currentEnd > itEnd) {
      // Right overlap. Not done.
      current->data.trimStartAtMost(itEnd - current->offset);
      it->data.append(current->data.move());
      current = &(*it);
      currentAlreadyInserted = true;
      DCHECK(!startOverlap);
      startOverlap = it + 1;
      endOverlap = it + 1;
    }
  }

  // Could have also been completely to the right of the last element.
  if (startOverlap && !currentAlreadyInserted) {
    DCHECK(endOverlap);
    DCHECK(
        *startOverlap != readBuffer.end() || *endOverlap == readBuffer.end());
    auto insertIt = readBuffer.erase(*startOverlap, *endOverlap);
    readBuffer.emplace(insertIt, std::move(*current));
    return;
  } else if (currentAlreadyInserted) {
    DCHECK(startOverlap);
    DCHECK(endOverlap);
    DCHECK(
        *startOverlap != readBuffer.end() || *endOverlap == readBuffer.end());
    readBuffer.erase(*startOverlap, *endOverlap);
    return;
  }
  auto last = readBuffer.end() - 1;
  if (current->offset > last->offset + last->data.chainLength()) {
    readBuffer.emplace_back(std::move(*current));
  }
}

void appendDataToReadBuffer(QuicStreamState& stream, StreamBuffer buffer) {
  appendDataToReadBufferCommon(
      stream,
      std::move(buffer),
      [&stream](uint64_t previousMaxOffsetObserved, uint64_t bufferEndOffset) {
        updateFlowControlOnStreamData(
            stream, previousMaxOffsetObserved, bufferEndOffset);
      });
}

void appendDataToReadBuffer(QuicCryptoStream& stream, StreamBuffer buffer) {
  appendDataToReadBufferCommon(
      stream, std::move(buffer), [](uint64_t, uint64_t) {});
}

std::pair<Buf, bool> readDataInOrderFromReadBuffer(
    QuicStreamLike& stream,
    uint64_t amount,
    bool sinkData) {
  auto remaining = amount;
  bool eof = false;
  Buf data;
  while ((amount == 0 || remaining != 0) && !stream.readBuffer.empty()) {
    auto curr = stream.readBuffer.begin();
    if (curr->offset > stream.currentReadOffset) {
      // The buffer is sorted in order of the left edge of the range,
      // if we find an item that is beyond the one we needed to read,
      // we should quit.
      break;
    }
    size_t currSize = curr->data.chainLength();

    // In the algorithm for the append function, we maintain the invariant that
    // the individual ranges are non-overlapping, thus if we get to this point,
    // we must have an offset which matches the read offset.
    CHECK_EQ(curr->offset, stream.currentReadOffset);

    uint64_t toRead =
        std::min<uint64_t>(currSize, amount == 0 ? currSize : remaining);
    std::unique_ptr<folly::IOBuf> splice;
    if (sinkData) {
      curr->data.trimStart(toRead);
    } else {
      splice = curr->data.split(toRead);
    }
    curr->offset += toRead;
    if (curr->data.chainLength() == 0) {
      eof = curr->eof;
      stream.readBuffer.pop_front();
    }
    if (!sinkData) {
      prependToBuf(data, std::move(splice));
    }
    if (amount != 0) {
      remaining -= toRead;
    }
    stream.currentReadOffset += toRead;
  }
  return std::make_pair(std::move(data), eof);
}

Buf readDataFromCryptoStream(QuicCryptoStream& stream, uint64_t amount) {
  return readDataInOrderFromReadBuffer(stream, amount).first;
}

std::pair<Buf, bool> readDataFromQuicStream(
    QuicStreamState& stream,
    uint64_t amount) {
  auto eof = stream.finalReadOffset &&
      stream.currentReadOffset >= *stream.finalReadOffset;
  if (eof) {
    if (stream.currentReadOffset == *stream.finalReadOffset) {
      stream.currentReadOffset += 1;
    }
    stream.conn.streamManager->updateReadableStreams(stream);
    stream.conn.streamManager->updatePeekableStreams(stream);
    return std::make_pair(nullptr, true);
  }

  uint64_t lastReadOffset = stream.currentReadOffset;

  Buf data;
  std::tie(data, eof) = readDataInOrderFromReadBuffer(stream, amount);
  // Update flow control before handling eof as eof is not subject to flow
  // control
  updateFlowControlOnRead(stream, lastReadOffset, Clock::now());
  eof = stream.finalReadOffset &&
      stream.currentReadOffset == *stream.finalReadOffset;
  if (eof) {
    stream.currentReadOffset += 1;
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updatePeekableStreams(stream);
  return std::make_pair(std::move(data), eof);
}

void peekDataFromQuicStream(
    QuicStreamState& stream,
    const folly::Function<void(StreamId id, const folly::Range<PeekIterator>&)
                              const>& peekCallback) {
  if (peekCallback) {
    peekCallback(
        stream.id,
        folly::Range<PeekIterator>(
            stream.readBuffer.cbegin(), stream.readBuffer.size()));
  }
}

/**
 * Same as readDataFromQuicStream(),
 * only releases existing data instead of returning it.
 */
void consumeDataFromQuicStream(QuicStreamState& stream, uint64_t amount) {
  bool eof = stream.finalReadOffset &&
      stream.currentReadOffset >= *stream.finalReadOffset;
  if (eof) {
    if (stream.currentReadOffset == *stream.finalReadOffset) {
      stream.currentReadOffset++;
    }
    stream.conn.streamManager->updateReadableStreams(stream);
    stream.conn.streamManager->updatePeekableStreams(stream);
    return;
  }

  uint64_t lastReadOffset = stream.currentReadOffset;

  readDataInOrderFromReadBuffer(stream, amount, true /* sinkData */);
  // Update flow control before handling eof as eof is not subject to flow
  // control
  updateFlowControlOnRead(stream, lastReadOffset, Clock::now());
  eof = stream.finalReadOffset &&
      stream.currentReadOffset == *stream.finalReadOffset;
  if (eof) {
    stream.currentReadOffset += 1;
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updatePeekableStreams(stream);
}

bool allBytesTillFinAcked(const QuicStreamState& stream) {
  /**
   * All bytes are acked if the following conditions are met:
   * 1. The app wrote a FIN
   * 2. We wrote the fin out to the network
   * 3. We have no bytes remaining to retransmit.
   * 4. We have no bytes left to write
   * 5. We have no bytes that are detected as lost.
   */
  return stream.finalWriteOffset &&
      stream.currentWriteOffset > *stream.finalWriteOffset &&
      stream.retransmissionBuffer.empty() && stream.writeBuffer.empty() &&
      stream.lossBuffer.empty();
}

void appendPendingStreamReset(
    QuicConnectionStateBase& conn,
    const QuicStreamState& stream,
    ApplicationErrorCode errorCode) {
  conn.pendingEvents.resets.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(stream.id),
      std::forward_as_tuple(
          stream.id,
          errorCode,
          std::min(
              stream.currentWriteOffset,
              stream.finalWriteOffset.value_or(
                  std::numeric_limits<uint64_t>::max()))));
}

uint64_t getLargestWriteOffsetSeen(const QuicStreamState& stream) {
  return stream.finalWriteOffset.value_or(
      stream.currentWriteOffset + stream.writeBuffer.chainLength());
}

uint64_t getStreamNextOffsetToDeliver(const QuicStreamState& stream) {
  auto minOffsetToDeliver = stream.currentWriteOffset;
  minOffsetToDeliver = std::min(
      minOffsetToDeliver,
      stream.retransmissionBuffer.empty()
          ? minOffsetToDeliver
          : stream.retransmissionBuffer[0].offset);
  minOffsetToDeliver = std::min(
      minOffsetToDeliver,
      stream.lossBuffer.empty() ? minOffsetToDeliver
                                : stream.lossBuffer[0].offset);
  return minOffsetToDeliver;
}

void cancelHandshakeCryptoStreamRetransmissions(QuicCryptoState& cryptoState) {
  // Cancel any retransmissions we might want to do for the crypto stream.
  // This does not include data that is already deemed as lost, or data that
  // is pending in the write buffer.
  cryptoState.initialStream.retransmissionBuffer.clear();
  cryptoState.handshakeStream.retransmissionBuffer.clear();
}

QuicCryptoStream* getCryptoStream(
    QuicCryptoState& cryptoState,
    EncryptionLevel encryptionLevel) {
  switch (encryptionLevel) {
    case EncryptionLevel::Initial:
      return &cryptoState.initialStream;
    case EncryptionLevel::Handshake:
      return &cryptoState.handshakeStream;
    case EncryptionLevel::EarlyData:
      // TODO: remove this when we implement EOED for
      // draft-17.
      return &cryptoState.handshakeStream;
    case EncryptionLevel::AppData:
      return &cryptoState.oneRttStream;
  }
  folly::assume_unreachable();
}

void processCryptoStreamAck(
    QuicCryptoStream& cryptoStream,
    uint64_t offset,
    uint64_t len) {
  auto ackedBuffer = std::lower_bound(
      cryptoStream.retransmissionBuffer.begin(),
      cryptoStream.retransmissionBuffer.end(),
      offset,
      [](const auto& buffer, const auto& offset) {
        return buffer.offset < offset;
      });

  if (ackedBuffer == cryptoStream.retransmissionBuffer.end() ||
      ackedBuffer->offset != offset || ackedBuffer->data.chainLength() != len) {
    // It's possible retransmissions of crypto data were canceled.
    return;
  }
  cryptoStream.retransmissionBuffer.erase(ackedBuffer);
}

bool streamFrameMatchesRetransmitBuffer(
    const QuicStreamState& stream,
    const WriteStreamFrame& streamFrame,
    const StreamBuffer& buf) {
  // There are 3 possible situations.
  // 1) Fully reliable mode: the buffer's and stream frame's offsets and lengths
  //    must match.
  // 2) Partially reliable mode: the retransmit queue buffer has been
  //    fully removed by an egress skip before the stream frame arrived.
  // 3) Partially reliable mode: the retransmit queue buffer was only
  //    partially trimmed.
  //    In this case, the retransmit buffer offset must be >= stream frame
  //    offset and retransmit buffer length must be <= stream frame len field
  //    vale. Also, the retransmit buffer [offset + length] must match stream
  //    frame [offset + length].

  bool match = false;
  if (stream.conn.partialReliabilityEnabled) {
    auto frameRightOffset = streamFrame.offset + streamFrame.len;
    if (frameRightOffset > buf.offset) {
      // There is overlap, buffer fully or partially matches.
      DCHECK(buf.offset >= streamFrame.offset);
      DCHECK(buf.data.chainLength() <= streamFrame.len);

      // The offsets and lengths in the stream frame and buffer may be
      // different, but their sum should stay the same (e.g. offset grows,
      // length shrinks but sum must be the same).
      //
      // Example: let's say we send data buf with offset=0 and len=11 and we
      // save a copy in retransmission queue. Then we send egress skip to offset
      // 6 and that trims that buf copy in retransmission queue to offset=6 and
      // len=5. Then we get an ACK for the original buf we sent with old
      // offset=0 and len=11 and comparing it to the already trimmed buf. The
      // offsets and lengths are going to be different, but their sum will be
      // the same.
      DCHECK_EQ(
          buf.offset + buf.data.chainLength(),
          streamFrame.offset + streamFrame.len);
      DCHECK_EQ(buf.eof, streamFrame.fin);
      match = true;
    } // else frameRightOffset <= buf.offset { ignore }
  } else {
    DCHECK_EQ(buf.offset, streamFrame.offset);
    DCHECK_EQ(buf.data.chainLength(), streamFrame.len);
    DCHECK_EQ(buf.eof, streamFrame.fin);
    match = true;
  }
  return match;
}
} // namespace quic
