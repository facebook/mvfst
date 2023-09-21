/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/IoBufQuicBatch.h>

#include <quic/common/SocketUtil.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>

namespace quic {
IOBufQuicBatch::IOBufQuicBatch(
    BatchWriterPtr&& batchWriter,
    bool threadLocal,
    QuicAsyncUDPSocketWrapper& sock,
    const folly::SocketAddress& peerAddress,
    QuicTransportStatsCallback* statsCallback,
    QuicClientConnectionState::HappyEyeballsState* happyEyeballsState)
    : batchWriter_(std::move(batchWriter)),
      threadLocal_(threadLocal),
      sock_(sock),
      peerAddress_(peerAddress),
      statsCallback_(statsCallback),
      happyEyeballsState_(happyEyeballsState) {}

bool IOBufQuicBatch::write(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t encodedSize) {
  result_.packetsSent++;
  result_.bytesSent += encodedSize;

  // see if we need to flush the prev buffer(s)
  if (batchWriter_->needsFlush(encodedSize)) {
    // continue even if we get an error here
    flush(FlushType::FLUSH_TYPE_ALWAYS);
  }

  // try to append the new buffers
  if (batchWriter_->append(
          std::move(buf),
          encodedSize,
          peerAddress_,
          threadLocal_ ? &sock_ : nullptr)) {
    // return if we get an error here
    return flush(FlushType::FLUSH_TYPE_ALWAYS);
  }

  return true;
}

bool IOBufQuicBatch::flush(FlushType flushType) {
  if (threadLocal_ &&
      (flushType == FlushType::FLUSH_TYPE_ALLOW_THREAD_LOCAL_DELAY)) {
    return true;
  }
  bool ret = flushInternal();
  reset();

  return ret;
}

void IOBufQuicBatch::reset() {
  batchWriter_->reset();
}

bool IOBufQuicBatch::isRetriableError(int err) {
  return err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS;
}

bool IOBufQuicBatch::flushInternal() {
  if (batchWriter_->empty()) {
    return true;
  }

  bool written = false;
  folly::Optional<int> firstSocketErrno;
  if (!happyEyeballsState_ || happyEyeballsState_->shouldWriteToFirstSocket) {
    auto consumed = batchWriter_->write(sock_, peerAddress_);
    if (consumed < 0) {
      firstSocketErrno = errno;
    }
    written = (consumed >= 0);
    if (happyEyeballsState_) {
      happyEyeballsState_->shouldWriteToFirstSocket =
          (consumed >= 0 || isRetriableError(errno));

      if (!happyEyeballsState_->shouldWriteToFirstSocket) {
        sock_.pauseRead();
      }
    }
  }

  // If error occurred on first socket, kick off second socket immediately
  if (!written && happyEyeballsState_ &&
      happyEyeballsState_->connAttemptDelayTimeout &&
      happyEyeballsState_->connAttemptDelayTimeout->isScheduled()) {
    happyEyeballsState_->connAttemptDelayTimeout->timeoutExpired();
    happyEyeballsState_->connAttemptDelayTimeout->cancelTimeout();
  }

  folly::Optional<int> secondSocketErrno;
  if (happyEyeballsState_ && happyEyeballsState_->shouldWriteToSecondSocket) {
    auto consumed = batchWriter_->write(
        *happyEyeballsState_->secondSocket,
        happyEyeballsState_->secondPeerAddress);
    if (consumed < 0) {
      secondSocketErrno = errno;
    }

    // written is marked true if either socket write succeeds
    written |= (consumed >= 0);
    happyEyeballsState_->shouldWriteToSecondSocket =
        (consumed >= 0 || isRetriableError(errno));
    if (!happyEyeballsState_->shouldWriteToSecondSocket) {
      happyEyeballsState_->secondSocket->pauseRead();
    }
  }

  if (!written && statsCallback_) {
    if (firstSocketErrno.has_value()) {
      QUIC_STATS(
          statsCallback_,
          onUDPSocketWriteError,
          QuicTransportStatsCallback::errnoToSocketErrorType(
              firstSocketErrno.value()));
    }
    if (secondSocketErrno.has_value()) {
      QUIC_STATS(
          statsCallback_,
          onUDPSocketWriteError,
          QuicTransportStatsCallback::errnoToSocketErrorType(
              secondSocketErrno.value()));
    }
  }

  // If we have no happy eyeballs state, we only care if the first socket had
  // an error. Otherwise we check both.
  if ((!happyEyeballsState_ && firstSocketErrno.has_value() &&
       !isRetriableError(firstSocketErrno.value())) ||
      (happyEyeballsState_ && !happyEyeballsState_->shouldWriteToFirstSocket &&
       !happyEyeballsState_->shouldWriteToSecondSocket)) {
    auto firstSocketErrorMsg = firstSocketErrno.has_value()
        ? folly::to<std::string>(
              folly::errnoStr(firstSocketErrno.value()), ", ")
        : "";
    auto secondSocketErrorMsg = secondSocketErrno.has_value()
        ? folly::errnoStr(secondSocketErrno.value())
        : "";
    auto errorMsg =
        folly::to<std::string>(firstSocketErrorMsg, secondSocketErrorMsg);
    // Both sockets becomes fatal, close connection
    VLOG(4) << "Error writing to the socket " << errorMsg << " "
            << peerAddress_;

    // We can get write error for any reason, close the conn only if network
    // is unreachable, for all others, we throw a transport exception
    if (isNetworkUnreachable(errno)) {
      throw QuicInternalException(
          folly::to<std::string>("Error on socket write ", errorMsg),
          LocalErrorCode::CONNECTION_ABANDONED);
    } else {
      throw QuicTransportException(
          folly::to<std::string>("Error on socket write ", errorMsg),
          TransportErrorCode::INTERNAL_ERROR);
    }
  }

  if (!written) {
    // This can happen normally, so ignore. Now we treat most errors same
    // as a loss to avoid looping.
    return false; // done
  }

  return true; // success, not done yet
}
} // namespace quic
