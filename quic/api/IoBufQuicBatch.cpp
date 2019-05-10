/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/IoBufQuicBatch.h>

#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>

namespace quic {
IOBufQuicBatch::IOBufQuicBatch(
    std::unique_ptr<BatchWriter>&& batchWriter,
    folly::AsyncUDPSocket& sock,
    folly::SocketAddress& peerAddress,
    QuicConnectionStateBase& conn,
    QuicConnectionStateBase::HappyEyeballsState& happyEyeballsState)
    : batchWriter_(std::move(batchWriter)),
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
    flush();
  }

  // try to append the new buffers
  if (batchWriter_->append(std::move(buf), encodedSize)) {
    // return if we get an error here
    return flush();
  }

  return true;
}

bool IOBufQuicBatch::flush() {
  bool ret = flushInternal();
  reset();

  return ret;
}

void IOBufQuicBatch::setContinueOnNetworkUnreachable(
    bool continueOnNetworkUnreachable) {
  continueOnNetworkUnreachable_ = continueOnNetworkUnreachable;
}

void IOBufQuicBatch::reset() {
  batchWriter_->reset();
}

bool IOBufQuicBatch::isNetworkUnreachable(int err) {
  return err == EHOSTUNREACH || err == ENETUNREACH;
}

bool IOBufQuicBatch::isRetriableError(int err) {
  if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS ||
      err == EMSGSIZE) {
    return true;
  }
  auto now = Clock::now();
  if (continueOnNetworkUnreachable_ && isNetworkUnreachable(err)) {
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
      sock_.close();
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
      happyEyeballsState_.secondSocket->close();
    }
  }

  // TODO: handle ENOBUFS and backpressure the socket.
  if (!happyEyeballsState_.shouldWriteToFirstSocket &&
      !happyEyeballsState_.shouldWriteToSecondSocket) {
    // Both sockets becomes fatal, close connection
    int errnoCopy = errno;
    std::string errorMsg = folly::to<std::string>(
        folly::errnoStr(errnoCopy),
        (errnoCopy == EMSGSIZE)
            ? folly::to<std::string>(", pktSize=", batchWriter_->size())
            : "");
    VLOG(4) << "Error writing to the socket " << errorMsg << " "
            << peerAddress_;
    throw QuicTransportException(
        folly::to<std::string>("Error on socket write ", errorMsg),
        TransportErrorCode::INTERNAL_ERROR);
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
