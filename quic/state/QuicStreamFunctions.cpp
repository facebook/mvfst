/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/QuicStreamFunctions.h>

#include <quic/QuicException.h>
#include <quic/flowcontrol/QuicFlowController.h>

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
  auto neverWrittenBufMeta = (0 == stream.writeBufMeta.offset);
  uint64_t len = 0;
  if (data) {
    len = data->computeChainDataLength();
  }
  // Once data is written to writeBufMeta, no more data can be written to
  // writeBuffer. Write only an EOF is fine.
  CHECK(neverWrittenBufMeta || len == 0);
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

void writeBufMetaToQuicStream(
    QuicStreamState& stream,
    const BufferMeta& data,
    bool eof) {
  if (data.length > 0) {
    maybeWriteBlockAfterAPIWrite(stream);
  }
  auto realDataLength =
      stream.currentWriteOffset + stream.writeBuffer.chainLength();
  CHECK_GT(realDataLength, 0)
      << "Real data has to be written to a stream before any buffer meta is"
      << "written to it.";
  if (stream.writeBufMeta.offset == 0) {
    CHECK(!stream.finalWriteOffset.has_value())
        << "Buffer meta cannot be appended to a stream after we have seen EOM "
        << "in real data";
    stream.writeBufMeta.offset = realDataLength;
  }
  stream.writeBufMeta.length += data.length;
  if (eof) {
    stream.finalWriteOffset =
        stream.writeBufMeta.offset + stream.writeBufMeta.length;
    stream.writeBufMeta.eof = true;
  }
  updateFlowControlOnWriteToStream(stream, data.length);
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
      splice = curr->data.splitAtMost(toRead);
      DCHECK_EQ(splice->computeChainDataLength(), toRead);
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
  return stream.hasSentFIN() && stream.retransmissionBuffer.empty() &&
      stream.retransmissionBufMetas.empty() && stream.writeBuffer.empty() &&
      !stream.hasWritableBufMeta() && stream.lossBuffer.empty() &&
      stream.lossBufMetas.empty();
}

void appendPendingStreamReset(
    QuicConnectionStateBase& conn,
    const QuicStreamState& stream,
    ApplicationErrorCode errorCode) {
  /*
   * When BufMetas are written to the transport, but before they are written to
   * the network, writeBufMeta.offset would be assigned a value >
   * currentWriteOffset. For this reason, we can't simply use
   * min(max(currentWriteOffset, writeBufMeta.offset), finalWriteOffset) as the
   * final offset. We have to check if any BufMetas have been written to the
   * network. If we simply use min(max(currentWriteOffset, writeBufMeta.offset),
   * we risk using a value > peer's flow control limit.
   */
  bool writeBufWritten = stream.writeBufMeta.offset &&
      (stream.currentWriteOffset + stream.writeBuffer.chainLength() !=
       stream.writeBufMeta.offset);
  conn.pendingEvents.resets.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(stream.id),
      std::forward_as_tuple(
          stream.id,
          errorCode,
          std::min(
              writeBufWritten ? stream.writeBufMeta.offset
                              : stream.currentWriteOffset,
              stream.finalWriteOffset.value_or(
                  std::numeric_limits<uint64_t>::max()))));
}

uint64_t getLargestWriteOffsetSeen(const QuicStreamState& stream) {
  return stream.finalWriteOffset.value_or(std::max<uint64_t>(
      stream.currentWriteOffset + stream.writeBuffer.chainLength(),
      stream.writeBufMeta.offset + stream.writeBufMeta.length));
}

folly::Optional<uint64_t> getLargestWriteOffsetTxed(
    const QuicStreamState& stream) {
  // currentWriteOffset is really nextWriteOffset
  // when 0, it indicates nothing has been written yet
  if (stream.currentWriteOffset == 0 && stream.writeBufMeta.offset == 0) {
    return folly::none;
  }
  uint64_t currentWriteOffset =
      std::max<uint64_t>(stream.currentWriteOffset, stream.writeBufMeta.offset);
  return currentWriteOffset - 1;
}

folly::Optional<uint64_t> getLargestDeliverableOffset(
    const QuicStreamState& stream) {
  // If the acked intervals is not empty, then the furthest acked interval
  // starting at zero is the next offset. If there is no interval starting at
  // zero then we cannot deliver any offsets.
  if (stream.ackedIntervals.empty() ||
      stream.ackedIntervals.front().start != 0) {
    return folly::none;
  }
  return stream.ackedIntervals.front().end;
}

uint64_t getAckIntervalSetVersion(const QuicStreamState& stream) {
  return stream.ackedIntervals.insertVersion();
}

uint64_t getNumPacketsTxWithNewData(const QuicStreamState& stream) {
  return stream.numPacketsTxWithNewData;
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
    default:
      LOG(FATAL) << "Unhandled EncryptionLevel";
  }
  folly::assume_unreachable();
}

void processCryptoStreamAck(
    QuicCryptoStream& cryptoStream,
    uint64_t offset,
    uint64_t len) {
  auto ackedBuffer = cryptoStream.retransmissionBuffer.find(offset);
  if (ackedBuffer == cryptoStream.retransmissionBuffer.end() ||
      ackedBuffer->second->offset != offset ||
      ackedBuffer->second->data.chainLength() != len) {
    // It's possible retransmissions of crypto data were canceled.
    return;
  }
  cryptoStream.retransmissionBuffer.erase(ackedBuffer);
}
} // namespace quic
