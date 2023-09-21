/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <gtest/gtest.h>
#include <quic/client/connector/QuicConnector.h>
#include <quic/client/test/Mocks.h>
#include <quic/common/QuicAsyncUDPSocketWrapper.h>
#include <quic/common/test/TestClientUtils.h>
#include <quic/fizz/client/handshake/FizzClientQuicHandshakeContext.h>

using namespace ::testing;

namespace quic::test {

class QuicConnectorTest : public Test {
 public:
  void SetUp() override {
    connector_ = std::make_unique<QuicConnector>(&cb_);
  }

  std::shared_ptr<fizz::CertificateVerifier> createTestCertificateVerifier() {
    return std::make_shared<TestCertificateVerifier>();
  }

  void executeMockConnect(
      MockQuicClientTransport::TestType testType,
      std::chrono::milliseconds connectTimeout) {
    auto verifier = createTestCertificateVerifier();
    auto clientCtx = std::make_shared<fizz::client::FizzClientContext>();
    auto pskCache = std::make_shared<BasicQuicPskCache>();
    auto sock = std::make_unique<QuicAsyncUDPSocketWrapperImpl>(&eventBase_);
    auto fizzClientContext = FizzClientQuicHandshakeContext::Builder()
                                 .setFizzClientContext(clientCtx)
                                 .setCertificateVerifier(verifier)
                                 .setPskCache(pskCache)
                                 .build();

    quicClient_ = std::make_shared<MockQuicClientTransport>(
        testType, &eventBase_, std::move(sock), std::move(fizzClientContext));

    connector_->connect(quicClient_, connectTimeout);
  }

  folly::EventBase eventBase_;
  std::unique_ptr<QuicConnector> connector_;
  MockQuicConnectorCallback cb_;
  std::shared_ptr<MockQuicClientTransport> quicClient_;
};

TEST_F(QuicConnectorTest, TestConnectSuccess) {
  EXPECT_CALL(cb_, onConnectSuccess()).Times(1).WillOnce(Invoke([this]() {
    eventBase_.terminateLoopSoon();
  }));
  executeMockConnect(
      MockQuicClientTransport::TestType::Success,
      std::chrono::milliseconds(200));
  eventBase_.loopForever();
}

TEST_F(QuicConnectorTest, TestConnectFailure) {
  EXPECT_CALL(cb_, onConnectError(_))
      .Times(1)
      .WillOnce(Invoke([this](QuicError) { eventBase_.terminateLoopSoon(); }));
  executeMockConnect(
      MockQuicClientTransport::TestType::Failure,
      std::chrono::milliseconds(200));
  eventBase_.loopForever();
}

TEST_F(QuicConnectorTest, TestConnectTimeout) {
  EXPECT_CALL(cb_, onConnectError(_))
      .Times(1)
      .WillOnce(Invoke([this](QuicError) { eventBase_.terminateLoopSoon(); }));
  executeMockConnect(
      MockQuicClientTransport::TestType::Timeout, std::chrono::milliseconds(1));
  eventBase_.loopForever();
}

} // namespace quic::test
