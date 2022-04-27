/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocket.h>

#include <folly/io/async/EventBase.h>
#include <quic/common/BufUtil.h>

namespace quic {
namespace samples {
class EchoHandler : public quic::QuicSocket::ConnectionSetupCallback,
                    public quic::QuicSocket::ConnectionCallback,
                    public quic::QuicSocket::ReadCallback,
                    public quic::QuicSocket::WriteCallback,
                    public quic::QuicSocket::DatagramCallback {
 public:
  using StreamData = std::pair<BufQueue, bool>;

  explicit EchoHandler(folly::EventBase* evbIn, bool useDatagrams = false)
      : evb(evbIn), useDatagrams_(useDatagrams) {}

  void setQuicSocket(std::shared_ptr<quic::QuicSocket> socket) {
    sock = socket;
    if (useDatagrams_) {
      auto res = sock->setDatagramCallback(this);
      CHECK(res.hasValue()) << res.error();
    }
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

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    LOG(ERROR) << "Socket error=" << toString(error.code) << " "
               << error.message;
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
      echo(id, input_[id]);
    }
  }

  void readError(quic::StreamId id, QuicError error) noexcept override {
    LOG(ERROR) << "Got read error on stream=" << id
               << " error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void onDatagramsAvailable() noexcept override {
    auto res = sock->readDatagrams();
    if (res.hasError()) {
      LOG(ERROR) << "readDatagrams() error: " << res.error();
      return;
    }
    LOG(INFO) << "received " << res->size() << " datagrams";
    echoDg(std::move(res.value()));
  }

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    LOG(INFO) << "socket is write ready with maxToSend=" << maxToSend;
    echo(id, input_[id]);
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    LOG(ERROR) << "write error with stream=" << id
               << " error=" << toString(error);
  }

  folly::EventBase* getEventBase() {
    return evb;
  }

  folly::EventBase* evb;
  std::shared_ptr<quic::QuicSocket> sock;

 private:
  void echo(quic::StreamId id, StreamData& data) {
    if (!data.second) {
      // only echo when eof is present
      return;
    }
    auto echoedData = folly::IOBuf::copyBuffer("echo ");
    echoedData->prependChain(data.first.move());
    auto res = sock->writeChain(id, std::move(echoedData), true, nullptr);
    if (res.hasError()) {
      LOG(ERROR) << "write error=" << toString(res.error());
    } else {
      // echo is done, clear EOF
      data.second = false;
    }
  }

  void echoDg(std::vector<quic::ReadDatagram> datagrams) {
    CHECK_GT(datagrams.size(), 0);
    for (const auto& datagram : datagrams) {
      auto echoedData = folly::IOBuf::copyBuffer("echo ");
      echoedData->prependChain(datagram.bufQueue().front()->cloneCoalesced());
      auto res = sock->writeDatagram(std::move(echoedData));
      if (res.hasError()) {
        LOG(ERROR) << "writeDatagram error=" << toString(res.error());
      }
    }
  }

  bool useDatagrams_;
  std::map<quic::StreamId, StreamData> input_;
};
} // namespace samples
} // namespace quic
