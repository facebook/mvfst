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
    QuicConnectionStateBase::HappyEyeballsState& happyEyeballsState)
    : batchWriter_(std::move(batchWriter)),
      sock_(sock),
      peerAddress_(peerAddress),
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
  return err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS ||
      err == EMSGSIZE ||
      (continueOnNetworkUnreachable_ && isNetworkUnreachable(err));
}

bool IOBufQuicBatch::flushInternal() {
  if (batchWriter_->empty()) {
    return true;
  }

  auto consumed = batchWriter_->write(sock_, peerAddress_);
  bool written = (consumed >= 0);

  // If retriable error occured on first socket, kick off second socket
  // immediately
  // TODO I think any error on first socket should trigger this though.
  if ((!written && isRetriableError(errno)) &&
      happyEyeballsState_.connAttemptDelayTimeout &&
      happyEyeballsState_.connAttemptDelayTimeout->isScheduled()) {
    happyEyeballsState_.connAttemptDelayTimeout->cancelTimeout();
    happyEyeballsStartSecondSocket(happyEyeballsState_);
  }

  // Write to second socket if there is no fatal error on first socket write
  if ((written || isRetriableError(errno)) &&
      happyEyeballsState_.shouldWriteToSecondSocket) {
    // TODO: if the errno is EMSGSIZE, and we move on with the second socket,
    // we actually miss the chance to fix our UDP packet size with the first
    // socket.
    consumed = batchWriter_->write(
        *happyEyeballsState_.secondSocket,
        happyEyeballsState_.secondPeerAddress);

    // written is marked false if either socket write fails
    // This causes write loop to exit early.
    // I am not sure if this is necessary but at least it should be OK
    written &= (consumed >= 0);
  }

  // TODO: handle ENOBUFS and backpressure the socket.
  if (!written && !isRetriableError(errno)) {
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

  return true; // success, not done yet
}
} // namespace quic
