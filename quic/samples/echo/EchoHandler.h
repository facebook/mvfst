/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/api/QuicSocket.h>

#include <folly/io/async/EventBase.h>
#include <quic/common/BufUtil.h>

namespace quic {
namespace samples {
class EchoHandler : public quic::QuicSocket::ConnectionCallback,
                    public quic::QuicSocket::ReadCallback,
                    public quic::QuicSocket::WriteCallback {
 public:
  using StreamData = std::pair<BufQueue, bool>;

  explicit EchoHandler(folly::EventBase* evbIn, bool prEnabled = false)
      : evb(evbIn), prEnabled_(prEnabled) {}

  void setQuicSocket(std::shared_ptr<quic::QuicSocket> socket) {
    sock = socket;
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "Got bidirectional stream id=" << id;
    sock->setReadCallback(id, this);
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    LOG(INFO) << "Got unidirectional stream id=" << id;
    sock->setReadCallback(id, this);
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode error) noexcept override {
    LOG(INFO) << "Got StopSending stream id=" << id << " error=" << error;
  }

  void onConnectionEnd() noexcept override {
    LOG(INFO) << "Socket closed";
  }

  void onConnectionError(
      std::pair<quic::QuicErrorCode, std::string> error) noexcept override {
    LOG(ERROR) << "Socket error=" << toString(error.first);
  }

  void readAvailable(quic::StreamId id) noexcept override {
    LOG(INFO) << "read available for stream id=" << id;

    auto res = sock->read(id, 0);
    if (res.hasError()) {
      LOG(ERROR) << "Got error=" << toString(res.error());
      return;
    }
    if (input_.find(id) == input_.end()) {
      input_.emplace(id, std::make_pair(BufQueue(), false));
    }
    quic::Buf data = std::move(res.value().first);
    bool eof = res.value().second;
    auto dataLen = (data ? data->computeChainDataLength() : 0);
    LOG(INFO) << "Got len=" << dataLen << " eof=" << uint32_t(eof)
              << " total=" << input_[id].first.chainLength() + dataLen
              << " data="
              << ((data) ? data->clone()->moveToFbString().toStdString()
                         : std::string());
    input_[id].first.append(std::move(data));
    input_[id].second = eof;
    if (eof) {
      if (prEnabled_) {
        skipSomeEchoSome(id, input_[id]);
      } else {
        echo(id, input_[id]);
      }
    }
  }

  void readError(
      quic::StreamId id,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
          error) noexcept override {
    LOG(ERROR) << "Got read error on stream=" << id
               << " error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void echo(quic::StreamId id, StreamData& data) {
    if (!data.second) {
      // only echo when eof is present
      return;
    }
    auto echoedData = folly::IOBuf::copyBuffer("echo ");
    echoedData->prependChain(data.first.move());
    auto res =
        sock->writeChain(id, std::move(echoedData), true, false, nullptr);
    if (res.hasError()) {
      LOG(ERROR) << "write error=" << toString(res.error());
    } else {
      // echo is done, clear EOF
      data.second = false;
    }
  }

  /**
   * Skips first part, echoes the second part.
   * E.g. "batman" -> "???man"
   */
  void skipSomeEchoSome(quic::StreamId id, StreamData& data) {
    if (!data.second) {
      // only echo when eof is present
      return;
    }
    auto& originalData = data.first;
    auto dataLen = originalData.chainLength();

    auto toSplit = dataLen / 2;

    if (toSplit > 0) {
      auto skipRes = sock->sendDataExpired(id, toSplit);
      if (skipRes.hasError()) {
        LOG(ERROR) << "skip error=" << toString(skipRes.error());
      } else {
        auto v = skipRes.value();
        if (v.has_value()) {
          LOG(INFO) << "new offset = " << v.value();
        } else {
          LOG(INFO) << "new offset doesn't have value";
        }
      }
    }

    originalData.splitAtMost(toSplit);

    auto res = sock->writeChain(id, originalData.move(), true, false, nullptr);
    if (res.hasError()) {
      LOG(ERROR) << "write error=" << toString(res.error());
    } else {
      // echo is done, clear EOF
      data.second = false;
    }
  }

  void onStreamWriteReady(
      quic::StreamId id,
      uint64_t maxToSend) noexcept override {
    LOG(INFO) << "socket is write ready with maxToSend=" << maxToSend;
    echo(id, input_[id]);
  }

  void onStreamWriteError(
      quic::StreamId id,
      std::pair<quic::QuicErrorCode, folly::Optional<folly::StringPiece>>
          error) noexcept override {
    LOG(ERROR) << "write error with stream=" << id
               << " error=" << toString(error);
  }

  folly::EventBase* getEventBase() {
    return evb;
  }

  folly::EventBase* evb;
  std::shared_ptr<quic::QuicSocket> sock;

 private:
  std::map<quic::StreamId, StreamData> input_;
  bool prEnabled_;
};
} // namespace samples
} // namespace quic
