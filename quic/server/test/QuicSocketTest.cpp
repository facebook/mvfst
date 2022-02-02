/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicSocket.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/samples/echo/EchoHandler.h>

#include <folly/io/async/EventBase.h>

#include <gtest/gtest.h>

using namespace quic;
using namespace testing;
using namespace quic::samples;
using folly::IOBuf;

class QuicSocketTest : public Test {
 public:
  void SetUp() override {
    socket_ = std::make_shared<MockQuicSocket>(&evb_, &handler_, &handler_);
    handler_.setQuicSocket(socket_);
  }

  void openStream(StreamId) {
    EXPECT_CALL(*socket_, setReadCallback(3, &handler_, _));
    socket_->connCb_->onNewBidirectionalStream(3);
  }

 protected:
  folly::EventBase evb_;
  EchoHandler handler_{&evb_};
  std::shared_ptr<MockQuicSocket> socket_;
};

std::pair<folly::IOBuf*, bool> readResult(const std::string& str, bool eof) {
  return std::pair<folly::IOBuf*, bool>(
      IOBuf::copyBuffer(str.c_str(), str.size()).release(), eof);
}

TEST_F(QuicSocketTest, simple) {
  InSequence enforceOrder;
  openStream(3);

  EXPECT_CALL(*socket_, readNaked(3, _))
      .WillOnce(Return(readResult("hello world", true)));
  EXPECT_CALL(*socket_, writeChain(3, _, true, nullptr))
      .WillOnce(Return(folly::unit));
  handler_.readAvailable(3);
}

TEST_F(QuicSocketTest, multiple_reads) {
  InSequence enforceOrder;
  openStream(3);

  EXPECT_CALL(*socket_, readNaked(3, _))
      .WillOnce(Return(readResult("hello ", false)));
  handler_.readAvailable(3);

  EXPECT_CALL(*socket_, readNaked(3, _))
      .WillOnce(Return(readResult("world", true)));
  EXPECT_CALL(*socket_, writeChain(3, _, true, nullptr))
      .WillOnce(Return(folly::unit));
  handler_.readAvailable(3);
}
