/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <quic/state/QuicStreamFunctions.h>

#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/flowcontrol/QuicFlowController.h>

#include <algorithm>

namespace {
void prependToBuf(quic::BufPtr& buf, quic::BufPtr toAppend) {
  if (buf) {
    buf->appendToChain(std::move(toAppend));
  } else {
    buf = std::move(toAppend);
  }
}
} // namespace

namespace quic {
quic::Expected<void, QuicError>
writeDataToQuicStream(QuicStreamState& stream, BufPtr data, bool eof) {
  uint64_t len = 0;
  if (data) {
    len = data->computeChainDataLength();
  }
  if (len > 0) {
    // We call this before updating the writeBuffer because we only want to
    // write a blocked frame first time the stream becomes blocked
    maybeWriteBlockAfterAPIWrite(stream);
  }
  stream.pendingWrites.append(data);
  stream.writeBuffer.append(std::move(data));
  if (eof) {
    auto bufferSize = stream.pendingWrites.chainLength();
    stream.finalWriteOffset = stream.currentWriteOffset + bufferSize;
  }
  auto result = updateFlowControlOnWriteToStream(stream, len);
  if (!result.has_value()) {
    return quic::make_unexpected(result.error());
  }
  stream.conn.streamManager->updateWritableStreams(stream);
  return {};
}

void writeDataToQuicStream(QuicCryptoStream& stream, BufPtr data) {
  stream.pendingWrites.append(data);
  stream.writeBuffer.append(std::move(data));
}

// Helper function which appends a raw data range to what MUST be a "tail" of
// a logic IOBuf chain, buf. The function will pack data into the available
// tail agressively, and allocate in terms of appendLen until the push is
// complete.
static void pushToTail(Buf* dst, BufPtr src, size_t allocSize) {
  size_t appended = 0;
  auto len = src->length();
  auto data = src->data();
  while (appended < len) {
    // If there's no tail room or that buffer is shared, trying to use the tail
    // will cause problems.
    if (dst->tailroom() == 0 || dst->isSharedOne()) {
      // If the buffer we are pushing has tail room, just use that one.
      // Otherwise, we have to allocate one.
      BufPtr newBuf;
      if (src->tailroom() > 0 && !src->isSharedOne()) {
        src->trimStart(appended);
        dst->appendChain(std::move(src));
        return;
      }
      newBuf = BufHelpers::createCombined(allocSize);
      dst->appendChain(std::move(newBuf));
      dst = dst->next();
    }
    auto toAppend = std::min(dst->tailroom(), len - appended);
    memcpy(dst->writableTail(), data, toAppend);
    dst->append(toAppend);
    appended += toAppend;
    data += toAppend;
  }
}

quic::Expected<void, QuicError> appendDataToReadBufferCommon(
    QuicStreamLike& stream,
    StreamBuffer buffer,
    uint32_t coalescingSize,
    FunctionRef<void(uint64_t, uint64_t)> connFlowControlVisitor) {
  auto& readBuffer = stream.readBuffer;
  auto it = readBuffer.begin();

  auto bufferEndOffset = buffer.offset + buffer.data.chainLength();

  Optional<uint64_t> bufferEofOffset;
  if (buffer.eof) {
    bufferEofOffset = bufferEndOffset;
  } else if (buffer.data.chainLength() == 0) {
    MVVLOG(10) << "Empty stream without EOF";
    return {};
  }

  if (stream.finalReadOffset && bufferEofOffset &&
      *stream.finalReadOffset != *bufferEofOffset) {
    return quic::make_unexpected(QuicError(
        QuicErrorCode(TransportErrorCode::FINAL_SIZE_ERROR),
        std::string("Invalid EOF")));
  } else if (bufferEofOffset) {
    // Do some consistency checks on the stream.
    if (stream.maxOffsetObserved > *bufferEofOffset) {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(TransportErrorCode::FINAL_SIZE_ERROR),
          std::string("EOF in middle of stream")));
    }
    stream.finalReadOffset = bufferEofOffset;
  } else if (stream.finalReadOffset) {
    // We did not receive a segment with an EOF set.
    if (buffer.offset + buffer.data.chainLength() > *stream.finalReadOffset) {
      return quic::make_unexpected(QuicError(
          QuicErrorCode(TransportErrorCode::FINAL_SIZE_ERROR),
          std::string("Invalid data after EOF")));
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
    return {};
  }

  if (buffer.offset < stream.currentReadOffset) {
    // trim the buffer to start from stream read offset.
    buffer.data.trimStartAtMost(stream.currentReadOffset - buffer.offset);
    buffer.offset = stream.currentReadOffset;
    if (buffer.data.chainLength() == 0) {
      return {};
    }
  }

  // Nothing in the buffer, just append it.
  if (it == readBuffer.end()) {
    readBuffer.emplace_back(std::move(buffer));
    return {};
  }

  // Start overlap will point to the first buffer that overlaps with the
  // current buffer and End overlap will point to the last buffer that overlaps.
  // They must always be set together.
  Optional<decltype(stream.readBuffer)::iterator> startOverlap;
  Optional<decltype(stream.readBuffer)::iterator> endOverlap;

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
      if (coalescingSize > kDefaultUDPSendPacketLen) {
        auto itData = it->data.move();
        auto itDataTail = itData->prev();
        auto currentData = current->data.move();
        while (currentData != nullptr) {
          auto rest = currentData->pop();
          pushToTail(itDataTail, std::move(currentData), coalescingSize);
          itDataTail = itData->prev();
          currentData = std::move(rest);
        }
        it->data.append(std::move(itData));
      } else {
        it->data.append(current->data.move());
      }
      current = &(*it);
      currentAlreadyInserted = true;
      MVDCHECK(!startOverlap);
      startOverlap = it + 1;
      endOverlap = it + 1;
    }
  }

  // Could have also been completely to the right of the last element.
  if (startOverlap && !currentAlreadyInserted) {
    MVDCHECK(endOverlap);
    MVDCHECK(
        *startOverlap != readBuffer.end() || *endOverlap == readBuffer.end());
    auto insertIt = readBuffer.erase(*startOverlap, *endOverlap);
    readBuffer.emplace(insertIt, std::move(*current));
    return {};
  } else if (currentAlreadyInserted) {
    MVDCHECK(startOverlap);
    MVDCHECK(endOverlap);
    MVDCHECK(
        *startOverlap != readBuffer.end() || *endOverlap == readBuffer.end());
    readBuffer.erase(*startOverlap, *endOverlap);
    return {};
  }
  auto last = readBuffer.end() - 1;
  if (current->offset > last->offset + last->data.chainLength()) {
    readBuffer.emplace_back(std::move(*current));
  }
  return {};
}

quic::Expected<void, QuicError> appendDataToReadBuffer(
    QuicStreamState& stream,
    StreamBuffer buffer) {
  return appendDataToReadBufferCommon(
      stream,
      std::move(buffer),
      0,
      [&stream](uint64_t previousMaxOffsetObserved, uint64_t bufferEndOffset) {
        return updateFlowControlOnStreamData(
            stream, previousMaxOffsetObserved, bufferEndOffset);
      });
}

quic::Expected<void, QuicError> appendDataToReadBuffer(
    QuicCryptoStream& stream,
    StreamBuffer buffer) {
  // Check crypto buffer size limit
  auto bufferEndOffset = buffer.offset + buffer.data.chainLength();
  if (bufferEndOffset > stream.currentReadOffset &&
      bufferEndOffset - stream.currentReadOffset >
          kDefaultMaxCryptoStreamBufferSize) {
    return quic::make_unexpected(QuicError(
        TransportErrorCode::CRYPTO_BUFFER_EXCEEDED,
        "crypto read buffer limit exceeded"));
  }
  return appendDataToReadBufferCommon(
      stream, std::move(buffer), 0, [](uint64_t, uint64_t) {});
}

std::pair<BufPtr, bool> readDataInOrderFromReadBuffer(
    QuicStreamLike& stream,
    uint64_t amount,
    bool sinkData) {
  auto remaining = amount;
  bool eof = false;
  BufPtr data;
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
    MVCHECK_EQ(curr->offset, stream.currentReadOffset);

    uint64_t toRead =
        std::min<uint64_t>(currSize, amount == 0 ? currSize : remaining);
    BufPtr splice;
    if (sinkData) {
      curr->data.trimStart(toRead);
    } else {
      splice = curr->data.splitAtMost(toRead);
      MVDCHECK_EQ(splice->computeChainDataLength(), toRead);
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

BufPtr readDataFromCryptoStream(QuicCryptoStream& stream, uint64_t amount) {
  return readDataInOrderFromReadBuffer(stream, amount).first;
}

quic::Expected<std::pair<BufPtr, bool>, QuicError> readDataFromQuicStream(
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

  BufPtr data;
  std::tie(data, eof) = readDataInOrderFromReadBuffer(stream, amount);
  // Update flow control before handling eof as eof is not subject to flow
  // control
  auto flowControlResult =
      updateFlowControlOnRead(stream, lastReadOffset, Clock::now());
  if (!flowControlResult.has_value()) {
    return quic::make_unexpected(flowControlResult.error());
  }
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
    FunctionRef<void(StreamId id, const folly::Range<PeekIterator>&)>
        peekCallback) {
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
quic::Expected<void, QuicError> consumeDataFromQuicStream(
    QuicStreamState& stream,
    uint64_t amount) {
  bool eof = stream.finalReadOffset &&
      stream.currentReadOffset >= *stream.finalReadOffset;
  if (eof) {
    if (stream.currentReadOffset == *stream.finalReadOffset) {
      stream.currentReadOffset++;
    }
    stream.conn.streamManager->updateReadableStreams(stream);
    stream.conn.streamManager->updatePeekableStreams(stream);
    return {};
  }

  uint64_t lastReadOffset = stream.currentReadOffset;

  readDataInOrderFromReadBuffer(stream, amount, true /* sinkData */);
  // Update flow control before handling eof as eof is not subject to flow
  // control
  auto flowControlResult =
      updateFlowControlOnRead(stream, lastReadOffset, Clock::now());
  if (!flowControlResult.has_value()) {
    return quic::make_unexpected(flowControlResult.error());
  }
  eof = stream.finalReadOffset &&
      stream.currentReadOffset == *stream.finalReadOffset;
  if (eof) {
    stream.currentReadOffset += 1;
  }
  stream.conn.streamManager->updateReadableStreams(stream);
  stream.conn.streamManager->updatePeekableStreams(stream);
  return {};
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
      stream.pendingWrites.empty() && stream.lossBuffer.empty();
}

void appendPendingStreamReset(
    QuicConnectionStateBase& conn,
    const QuicStreamState& stream,
    ApplicationErrorCode errorCode,
    Optional<uint64_t> reliableSize) {
  /*
   * The spec mandates that with multiple RESET_STREAM_AT or RESET_STREAM
   * frames, we must use the same value of finalSize. Although we don't store
   * previous values of finalSize to ensure that we use that same value
   * throughout, we still maintain this property, due to the following facts:
   *
   * 1. We only egress a RESET_STREAM_AT or RESET_STREAM frame when all data
   * upto the reliable reset offset has been egressed.
   * 2. The user is not allowed to increase the reliable size in subsequent
   * calls to resetStream().
   *
   * Therefore, if a RESET_STREAM_AT frame has been egressed, it means that the
   * data until the reliableSize in that frame has been egressed, so we end up
   * with the same calculation of the finalSize in subsequent RESET_STREAM or
   * RESET_STREAM_AT frames by virtue of the fact that it's the maxiumum of the
   * current write offset and the new reliable size.
   */
  uint64_t finalSize = stream.currentWriteOffset;
  if (reliableSize) {
    // It's possible that we've queued up data at the socket, but haven't yet
    // written it out to the wire, so stream.currentWriteOffset could be
    // lagging behind reliableSize
    finalSize = std::max(finalSize, *reliableSize);
  }
  finalSize = std::min(
      finalSize,
      stream.finalWriteOffset.value_or(std::numeric_limits<uint64_t>::max()));

  conn.pendingEvents.resets.emplace(
      std::piecewise_construct,
      std::forward_as_tuple(stream.id),
      std::forward_as_tuple(stream.id, errorCode, finalSize, reliableSize));
}

uint64_t getLargestWriteOffsetSeen(const QuicStreamState& stream) {
  return stream.finalWriteOffset.value_or(
      stream.currentWriteOffset + stream.pendingWrites.chainLength());
}

Optional<uint64_t> getLargestWriteOffsetTxed(const QuicStreamState& stream) {
  // currentWriteOffset is really nextWriteOffset
  // when 0, it indicates nothing has been written yet
  if (stream.currentWriteOffset == 0) {
    return std::nullopt;
  }
  return stream.currentWriteOffset - 1;
}

Optional<uint64_t> getLargestDeliverableOffset(const QuicStreamState& stream) {
  // If the acked intervals is not empty, then the furthest acked interval
  // starting at zero is the next offset. If there is no interval starting at
  // zero then we cannot deliver any offsets.
  if (stream.ackedIntervals.empty() ||
      stream.ackedIntervals.front().start != 0) {
    return std::nullopt;
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
      MVCHECK(false, "Unhandled EncryptionLevel");
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

void processTxStopSending(QuicStreamState& stream) {
  // no longer interested in ingress
  auto id = stream.id;
  auto& streamManager = stream.conn.streamManager;
  stream.recvState = StreamRecvState::Closed;
  stream.readBuffer.clear();
  streamManager->readableStreams().erase(id);
  if (stream.inTerminalStates()) {
    streamManager->addClosed(id);
  }
}
} // namespace quic
