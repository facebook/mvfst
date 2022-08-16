/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <quic/api/QuicSocket.h>
#include <quic/api/test/MockQuicSocket.h>
#include <quic/api/test/Mocks.h>

using namespace quic;
using namespace testing;

class QuicSocketTest : public Test {
 public:
  void SetUp() override {
    socket_ = std::make_shared<MockQuicSocket>();
  }

 protected:
  std::shared_ptr<MockQuicSocket> socket_;
};

TEST_F(QuicSocketTest, ObserverAddRemoveNoContainer) {
  auto obs1 = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*socket_, getSocketObserverContainer()).WillOnce(Return(nullptr));
  EXPECT_FALSE(socket_->addObserver(obs1));

  auto obs2 = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*socket_, getSocketObserverContainer()).WillOnce(Return(nullptr));
  EXPECT_FALSE(socket_->removeObserver(obs1));
}

TEST_F(QuicSocketTest, ObserverAddRemoveWithContainer) {
  auto observerContainer =
      std::make_shared<quic::SocketObserverContainer>(socket_.get());

  InSequence s;

  auto obs1 = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*socket_, getSocketObserverContainer())
      .WillOnce(Return(observerContainer.get()));
  EXPECT_CALL(*obs1, observerAttach(socket_.get()));
  EXPECT_TRUE(socket_->addObserver(obs1.get()));

  EXPECT_EQ(1, observerContainer->numObservers());

  auto obs2 = std::make_unique<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*socket_, getSocketObserverContainer())
      .WillOnce(Return(observerContainer.get()));
  EXPECT_CALL(*obs1, observerDetach(socket_.get()));
  EXPECT_TRUE(socket_->removeObserver(obs1.get()));
}

TEST_F(QuicSocketTest, ObserverSharedPtrAddRemoveNoContainer) {
  auto obs1 = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*socket_, getSocketObserverContainer()).WillOnce(Return(nullptr));
  EXPECT_FALSE(socket_->addObserver(obs1));

  auto obs2 = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*socket_, getSocketObserverContainer()).WillOnce(Return(nullptr));
  EXPECT_FALSE(socket_->removeObserver(obs1));
}

TEST_F(QuicSocketTest, ObserverSharedPtrAddRemoveWithContainer) {
  auto observerContainer =
      std::make_shared<quic::SocketObserverContainer>(socket_.get());

  InSequence s;

  auto obs1 = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*socket_, getSocketObserverContainer())
      .WillOnce(Return(observerContainer.get()));
  EXPECT_CALL(*obs1, observerAttach(socket_.get()));
  EXPECT_TRUE(socket_->addObserver(obs1));

  EXPECT_EQ(1, observerContainer->numObservers());

  auto obs2 = std::make_shared<StrictMock<MockLegacyObserver>>();
  EXPECT_CALL(*socket_, getSocketObserverContainer())
      .WillOnce(Return(observerContainer.get()));
  EXPECT_CALL(*obs1, observerDetach(socket_.get()));
  EXPECT_TRUE(socket_->removeObserver(obs1));
}
