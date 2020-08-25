// Copyright 2004-present Facebook. All Rights Reserved.

#include <quic/client/state/ClientStateMachine.h>
#include <quic/client/handshake/CachedServerTransportParameters.h>
#include <quic/client/handshake/ClientHandshake.h>
#include <quic/handshake/CryptoFactory.h>
#include <quic/handshake/TransportParameters.h>
#include "quic/client/test/Mocks.h"

using namespace ::testing;
using namespace std::literals::chrono_literals;

namespace quic::test {

namespace {
// Use non-default values to test for nops
constexpr auto idleTimeout = kDefaultIdleTimeout + 1s;
constexpr auto maxRecvPacketSize = 1420;
constexpr auto initialMaxData = kDefaultConnectionWindowSize + 2;
constexpr auto initialMaxStreamDataBidiLocal = kDefaultStreamWindowSize + 3;
constexpr auto initialMaxStreamDataBidiRemote = kDefaultStreamWindowSize + 4;
constexpr auto initialMaxStreamDataUni = kDefaultStreamWindowSize + 5;
constexpr auto initialMaxStreamsBidi = kDefaultMaxStreamsBidirectional + 6;
constexpr auto initialMaxStreamsUni = kDefaultMaxStreamsUnidirectional + 7;
const CachedServerTransportParameters kParams{
    std::chrono::milliseconds(idleTimeout).count(),
    maxRecvPacketSize,
    initialMaxData,
    initialMaxStreamDataBidiLocal,
    initialMaxStreamDataBidiRemote,
    initialMaxStreamDataUni,
    initialMaxStreamsBidi,
    initialMaxStreamsUni};
} // namespace

class ClientStateMachineTest : public Test {
 public:
  void SetUp() override {
    mockFactory_ = std::make_shared<MockClientHandshakeFactory>();
    EXPECT_CALL(*mockFactory_, makeClientHandshake(_))
        .WillOnce(Invoke(
            [&](QuicClientConnectionState* conn)
                -> std::unique_ptr<quic::ClientHandshake> {
              auto handshake = std::make_unique<MockClientHandshake>(conn);
              mockHandshake_ = handshake.get();
              return handshake;
            }));
    client_ = std::make_unique<QuicClientConnectionState>(mockFactory_);
  }

  std::shared_ptr<MockClientHandshakeFactory> mockFactory_;
  MockClientHandshake* mockHandshake_;
  std::unique_ptr<QuicClientConnectionState> client_;
};

TEST_F(ClientStateMachineTest, TestUpdateTransportParamsNotIgnorePathMTU) {
  updateTransportParamsFromCachedEarlyParams(*client_, kParams);
  EXPECT_EQ(client_->udpSendPacketLen, kDefaultUDPSendPacketLen);
}

TEST_F(ClientStateMachineTest, TestUpdateTransportParamsFromCachedEarlyParams) {
  client_->transportSettings.canIgnorePathMTU = true;

  updateTransportParamsFromCachedEarlyParams(*client_, kParams);
  EXPECT_EQ(client_->peerIdleTimeout, idleTimeout);
  EXPECT_EQ(client_->udpSendPacketLen, maxRecvPacketSize);
  EXPECT_EQ(client_->flowControlState.peerAdvertisedMaxOffset, initialMaxData);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal,
      initialMaxStreamDataBidiLocal);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiRemote,
      initialMaxStreamDataBidiRemote);
  EXPECT_EQ(
      client_->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni,
      initialMaxStreamDataUni);

  for (unsigned long i = 0; i < initialMaxStreamsBidi; i++) {
    EXPECT_TRUE(
        client_->streamManager->createNextBidirectionalStream().hasValue());
  }
  EXPECT_TRUE(
      client_->streamManager->createNextBidirectionalStream().hasError());
  for (unsigned long i = 0; i < initialMaxStreamsUni; i++) {
    EXPECT_TRUE(
        client_->streamManager->createNextUnidirectionalStream().hasValue());
  }
  EXPECT_TRUE(
      client_->streamManager->createNextUnidirectionalStream().hasError());
}

} // namespace quic::test
