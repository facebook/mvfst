/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/test/TestTransportUtils.h>

#include <quic/common/StringUtils.h>
#include <quic/congestion_control/QuicCubic.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/QuicPathManager.h>
#include <quic/state/QuicStreamManager.h>

namespace quic::test {

std::unique_ptr<MockAead> createNoOpAead(uint64_t cipherOverhead) {
  return createNoOpAeadImpl<MockAead>(cipherOverhead);
}

quic::Expected<std::unique_ptr<MockPacketNumberCipher>, QuicError>
createNoOpHeaderCipher() {
  auto headerCipher =
      std::make_unique<testing::NiceMock<MockPacketNumberCipher>>();
  ON_CALL(*headerCipher, mask(testing::_))
      .WillByDefault(testing::Return(HeaderProtectionMask{}));
  ON_CALL(*headerCipher, keyLength()).WillByDefault(testing::Return(16));
  return headerCipher;
}

void initializePathManagerState(QuicConnectionStateBase& conn) {
  if (!conn.pathManager) {
    conn.pathManager = std::make_unique<QuicPathManager>(conn);
  }
  auto addPathRes = conn.pathManager->addValidatedPath(
      folly::SocketAddress("::1", 12345), conn.peerAddress);
  CHECK(!addPathRes.hasError())
      << "Failed to add validated path: " << addPathRes.error();
  conn.currentPathId = addPathRes.value();
}

std::unique_ptr<QuicConnectionStateBase> createTestQuicConnectionState() {
  auto conn = std::make_unique<QuicConnectionStateBase>(QuicNodeType::Server);
  conn->cryptoState = std::make_unique<QuicCryptoState>();
  conn->congestionController = std::make_unique<Cubic>(*conn);
  conn->connectionTime = Clock::now();
  conn->supportedVersions = std::vector<QuicVersion>{
      {QuicVersion::MVFST,
       QuicVersion::MVFST_EXPERIMENTAL,
       QuicVersion::MVFST_EXPERIMENTAL2,
       QuicVersion::MVFST_EXPERIMENTAL3,
       QuicVersion::MVFST_EXPERIMENTAL4,
       QuicVersion::MVFST_EXPERIMENTAL5,
       QuicVersion::MVFST_ALIAS,
       QuicVersion::QUIC_V1,
       QuicVersion::QUIC_V1_ALIAS,
       QuicVersion::QUIC_V1_ALIAS2,
       QuicVersion::MVFST_PRIMING}};
  conn->originalVersion = QuicVersion::MVFST;
  updateFlowControlStateWithSettings(
      conn->flowControlState, conn->transportSettings);
  conn->streamManager = std::make_unique<QuicStreamManager>(
      *conn, conn->nodeType, conn->transportSettings);
  conn->pathManager = std::make_unique<QuicPathManager>(*conn);
  conn->connIdsRetiringSoon.emplace(SmallVec<ConnectionId, 5>{});
  return conn;
}

TrafficKey getQuicTestKey() {
  TrafficKey testKey;
  auto keyOpt = quic::unhexlify("000102030405060708090A0B0C0D0E0F");
  CHECK(keyOpt.has_value()) << "Failed to unhexlify test key";
  testKey.key = folly::IOBuf::copyBuffer(keyOpt.value());

  auto ivOpt = quic::unhexlify("000102030405060708090A0B");
  CHECK(ivOpt.has_value()) << "Failed to unhexlify test IV";
  testKey.iv = folly::IOBuf::copyBuffer(ivOpt.value());
  return testKey;
}

} // namespace quic::test
