/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/IoBufQuicBatch.h>

#include <quic/common/SocketUtil.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>

namespace quic {
IOBufQuicBatch::IOBufQuicBatch(
    BatchWriterPtr&& batchWriter,
    bool threadLocal,
    folly::AsyncUDPSocket& sock,
    folly::SocketAddress& peerAddress,
    QuicConnectionStateBase& conn,
    QuicConnectionStateBase::HappyEyeballsState& happyEyeballsState)
    : batchWriter_(std::move(batchWriter)),
      threadLocal_(threadLocal),
      sock_(sock),
      peerAddress_(peerAddress),
      conn_(conn),
      happyEyeballsState_(happyEyeballsState) {}

bool IOBufQuicBatch::write(
    std::unique_ptr<folly::IOBuf>&& buf,
    size_t encodedSize) {
  pktSent_++;

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
  if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS ||
      err == EMSGSIZE) {
    return true;
  }
  auto now = Clock::now();
  if (conn_.transportSettings.continueOnNetworkUnreachable &&
      isNetworkUnreachable(err)) {
    if (!conn_.continueOnNetworkUnreachableDeadline) {
      conn_.continueOnNetworkUnreachableDeadline =
          now + conn_.transportSettings.continueOnNetworkUnreachableDuration;
    }
    return now <= *conn_.continueOnNetworkUnreachableDeadline;
  }
  return false;
}

bool IOBufQuicBatch::flushInternal() {
  if (batchWriter_->empty()) {
    return true;
  }

  bool written = false;
  if (happyEyeballsState_.shouldWriteToFirstSocket) {
    auto consumed = batchWriter_->write(sock_, peerAddress_);
    written = (consumed >= 0);
    happyEyeballsState_.shouldWriteToFirstSocket =
        (consumed >= 0 || isRetriableError(errno));

    if (!happyEyeballsState_.shouldWriteToFirstSocket) {
      sock_.pauseRead();
    }
  }

  // If error occured on first socket, kick off second socket immediately
  if (!written && happyEyeballsState_.connAttemptDelayTimeout &&
      happyEyeballsState_.connAttemptDelayTimeout->isScheduled()) {
    happyEyeballsState_.connAttemptDelayTimeout->cancelTimeout();
    happyEyeballsStartSecondSocket(happyEyeballsState_);
  }

  if (happyEyeballsState_.shouldWriteToSecondSocket) {
    // TODO: if the errno is EMSGSIZE, and we move on with the second socket,
    // we actually miss the chance to fix our UDP packet size with the first
    // socket.
    auto consumed = batchWriter_->write(
        *happyEyeballsState_.secondSocket,
        happyEyeballsState_.secondPeerAddress);

    // written is marked true if either socket write succeeds
    written |= (consumed >= 0);
    happyEyeballsState_.shouldWriteToSecondSocket =
        (consumed >= 0 || isRetriableError(errno));
    if (!happyEyeballsState_.shouldWriteToSecondSocket) {
      happyEyeballsState_.secondSocket->pauseRead();
    }
  }

  int errnoCopy = 0;
  if (!written) {
    errnoCopy = errno;
    QUIC_STATS(
        conn_.statsCallback,
        onUDPSocketWriteError,
        QuicTransportStatsCallback::errnoToSocketErrorType(errnoCopy));
  }

  // TODO: handle ENOBUFS and backpressure the socket.
  if (!happyEyeballsState_.shouldWriteToFirstSocket &&
      !happyEyeballsState_.shouldWriteToSecondSocket) {
    // Both sockets becomes fatal, close connection
    std::string errorMsg = folly::to<std::string>(
        folly::errnoStr(errnoCopy),
        (errnoCopy == EMSGSIZE)
            ? folly::to<std::string>(", pktSize=", batchWriter_->size())
            : "");
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
    // This can happen normally, so ignore for now. Now we treat EAGAIN same
    // as a loss to avoid looping.
    // TODO: Remove once we use write event from libevent.
    return false; // done
  }

  // Reset the deadline after successful write
  conn_.continueOnNetworkUnreachableDeadline = folly::none;

  return true; // success, not done yet
}
} // namespace quic
