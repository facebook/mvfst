/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/api/QuicSocket.h>
#include <quic/common/MvfstLogging.h>

#include <quic/common/BufUtil.h>

namespace quic::samples {
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
      CHECK(res.has_value()) << res.error();
    }
  }

  void onNewBidirectionalStream(quic::StreamId id) noexcept override {
    MVLOG_INFO << "Got bidirectional stream id=" << id;
    CHECK(sock->setReadCallback(id, this).has_value());
  }

  void onNewUnidirectionalStream(quic::StreamId id) noexcept override {
    MVLOG_INFO << "Got unidirectional stream id=" << id;
    CHECK(sock->setReadCallback(id, this).has_value());
  }

  void onStopSending(
      quic::StreamId id,
      quic::ApplicationErrorCode error) noexcept override {
    MVLOG_INFO << "Got StopSending stream id=" << id << " error=" << error;
  }

  void onConnectionEnd() noexcept override {
    MVLOG_INFO << "Socket closed";
  }

  void onConnectionSetupError(QuicError error) noexcept override {
    onConnectionError(std::move(error));
  }

  void onConnectionError(QuicError error) noexcept override {
    MVLOG_ERROR << "Socket error=" << toString(error.code) << " "
                << error.message;
  }

  void readAvailable(quic::StreamId id) noexcept override {
    MVLOG_INFO << "read available for stream id=" << id;

    auto res = sock->read(id, 0);
    if (res.hasError()) {
      MVLOG_ERROR << "Got error=" << toString(res.error());
      CHECK(sock->setReadCallback(id, nullptr).has_value());
      return;
    }
    if (input_.find(id) == input_.end()) {
      input_.emplace(id, std::make_pair(BufQueue(), false));
    }
    quic::BufPtr data = std::move(res.value().first);
    bool eof = res.value().second;
    auto dataLen = (data ? data->computeChainDataLength() : 0);
    MVLOG_INFO << "Got len=" << dataLen << " eof=" << uint32_t(eof)
               << " total=" << input_[id].first.chainLength() + dataLen
               << " data="
               << ((data) ? data->clone()->toString() : std::string());
    input_[id].first.append(std::move(data));
    input_[id].second = eof;
    if (eof) {
      echo(id, input_[id]);
      MVLOG_INFO << "uninstalling read callback";
      CHECK(sock->setReadCallback(id, nullptr).has_value());
    }
  }

  void readError(quic::StreamId id, QuicError error) noexcept override {
    MVLOG_ERROR << "Got read error on stream=" << id
                << " error=" << toString(error);
    // A read error only terminates the ingress portion of the stream state.
    // Your application should probably terminate the egress portion via
    // resetStream
  }

  void onDatagramsAvailable() noexcept override {
    auto res = sock->readDatagrams();
    if (res.hasError()) {
      MVLOG_ERROR << "readDatagrams() error: " << res.error();
      return;
    }
    MVLOG_INFO << "received " << res->size() << " datagrams";
    echoDg(std::move(res.value()));
  }

  void onStreamWriteReady(quic::StreamId id, uint64_t maxToSend) noexcept
      override {
    MVLOG_INFO << "socket is write ready with maxToSend=" << maxToSend;
    echo(id, input_[id]);
  }

  void onStreamWriteError(quic::StreamId id, QuicError error) noexcept
      override {
    MVLOG_ERROR << "write error with stream=" << id
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
    auto echoedData = BufHelpers::copyBuffer("echo ");
    echoedData->appendToChain(data.first.move());
    auto res = sock->writeChain(id, std::move(echoedData), true, nullptr);
    if (res.hasError()) {
      MVLOG_ERROR << "write error=" << toString(res.error());
    } else {
      // echo is done, clear EOF
      data.second = false;
    }
  }

  void echoDg(std::vector<quic::ReadDatagram> datagrams) {
    CHECK_GT(datagrams.size(), 0);
    for (const auto& datagram : datagrams) {
      auto echoedData = BufHelpers::copyBuffer("echo ");
      echoedData->appendToChain(datagram.bufQueue().front()->cloneCoalesced());
      auto res = sock->writeDatagram(std::move(echoedData));
      if (res.hasError()) {
        MVLOG_ERROR << "writeDatagram error=" << toString(res.error());
      }
    }
  }

  bool useDatagrams_;
  using PerStreamData = std::map<quic::StreamId, StreamData>;
  PerStreamData input_;
};
} // namespace quic::samples
