/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>
#include <quic/common/udpsocket/FollyQuicAsyncUDPSocket.h>
#include <quic/common/udpsocket/test/QuicAsyncUDPSocketTestBase.h>
#include <array>
#include <cstdint>
#include <utility>

using namespace ::testing;

class AddressCountingFollyQuicAsyncUDPSocket
    : public quic::FollyQuicAsyncUDPSocket {
 public:
  explicit AddressCountingFollyQuicAsyncUDPSocket(
      std::shared_ptr<quic::FollyQuicEventBase> qEvb)
      : quic::FollyQuicAsyncUDPSocket(std::move(qEvb)) {}

  quic::Expected<quic::SocketAddress, quic::QuicError> address()
      const override {
    ++addressCallCount_;
    return quic::FollyQuicAsyncUDPSocket::address();
  }

  void resetAddressCallCount() {
    addressCallCount_ = 0;
  }

  uint32_t getAddressCallCount() const {
    return addressCallCount_;
  }

 private:
  mutable uint32_t addressCallCount_{0};
};

class FollyQuicAsyncUDPSocketProvider {
 public:
  static std::shared_ptr<quic::QuicAsyncUDPSocket> makeQuicAsyncUDPSocket() {
    static folly::EventBase fEvb;
    auto evb = std::make_shared<quic::FollyQuicEventBase>(&fEvb);
    return std::make_shared<quic::FollyQuicAsyncUDPSocket>(evb);
  }
};

using FollyQuicAsyncUDPSocketType = Types<FollyQuicAsyncUDPSocketProvider>;

INSTANTIATE_TYPED_TEST_SUITE_P(
    FollyQuicAsyncUDPSocketTest, // Instance name
    QuicAsyncUDPSocketTest, // Test case name
    FollyQuicAsyncUDPSocketType); // Type list

TEST(FollyQuicAsyncUDPSocketTest, RecvmmsgNetworkDataGetsLocalAddressOnce) {
  folly::EventBase fEvb;
  auto qEvb = std::make_shared<quic::FollyQuicEventBase>(&fEvb);
  AddressCountingFollyQuicAsyncUDPSocket sock(qEvb);

  ASSERT_FALSE(sock.bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  sock.resetAddressCallCount();

  quic::NetworkData networkData;
  size_t totalData = 0;
  auto result = sock.recvmmsgNetworkData(
      /*readBufferSize=*/2048,
      /*numPackets=*/8,
      networkData,
      totalData);

  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(sock.getAddressCallCount(), 1u);
}

// Two senders on distinct local ports each send one datagram to a receiver
// socket; assert recvmmsgNetworkData populates ReceivedUdpPacket::peerAddress
// on every packet with the matching source.
TEST(FollyQuicAsyncUDPSocketTest, RecvmmsgNetworkDataPopulatesPerPacketPeer) {
  folly::EventBase fEvb;
  auto qEvb = std::make_shared<quic::FollyQuicEventBase>(&fEvb);

  // readCb must outlive recvSock: recvSock's destructor calls onReadClosed.
  quic::test::MockUDPReadCallback readCb;

  auto recvSock = std::make_shared<quic::FollyQuicAsyncUDPSocket>(qEvb);
  ASSERT_FALSE(recvSock->bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
  auto recvAddrRes = recvSock->address();
  ASSERT_FALSE(recvAddrRes.hasError());
  const auto& recvAddr = recvAddrRes.value();

  auto makeSender = [&]() {
    auto s = std::make_shared<quic::FollyQuicAsyncUDPSocket>(qEvb);
    EXPECT_FALSE(s->bind(folly::SocketAddress("127.0.0.1", 0)).hasError());
    return s;
  };
  auto sender1 = makeSender();
  auto sender2 = makeSender();
  auto sender1AddrRes = sender1->address();
  auto sender2AddrRes = sender2->address();
  ASSERT_FALSE(sender1AddrRes.hasError());
  ASSERT_FALSE(sender2AddrRes.hasError());
  const auto& sender1Addr = sender1AddrRes.value();
  const auto& sender2Addr = sender2AddrRes.value();
  ASSERT_NE(sender1Addr.getPort(), sender2Addr.getPort());

  // Both writes before pumping the loop so they arrive in one batch.
  auto buf1 = quic::BufHelpers::copyBuffer("from-sender-1");
  std::array<iovec, quic::kNumIovecBufferChains> iov1{};
  size_t iov1Len = buf1->fillIov(iov1.data(), iov1.size()).numIovecs;
  ASSERT_GT(sender1->write(recvAddr, iov1.data(), iov1Len), 0);

  auto buf2 = quic::BufHelpers::copyBuffer("from-sender-2");
  std::array<iovec, quic::kNumIovecBufferChains> iov2{};
  size_t iov2Len = buf2->fillIov(iov2.data(), iov2.size()).numIovecs;
  ASSERT_GT(sender2->write(recvAddr, iov2.data(), iov2Len), 0);

  EXPECT_CALL(readCb, shouldOnlyNotify()).WillRepeatedly(testing::Return(true));

  std::vector<folly::SocketAddress> seenPeers;
  std::vector<std::string> seenPayloads;
  EXPECT_CALL(readCb, onNotifyDataAvailable_(testing::_))
      .WillRepeatedly([&](quic::QuicAsyncUDPSocket& sock) {
        quic::NetworkData networkData;
        networkData.reserve(8);
        size_t totalData = 0;
        auto result = sock.recvmmsgNetworkData(
            /*readBufferSize=*/2048,
            /*numPackets=*/8,
            networkData,
            totalData);
        ASSERT_TRUE(result.has_value());
        for (auto& pkt : networkData.getPackets()) {
          ASSERT_TRUE(pkt.peerAddress.has_value())
              << "every packet must carry a per-packet peerAddress";
          seenPeers.push_back(*pkt.peerAddress);
          seenPayloads.emplace_back(
              reinterpret_cast<const char*>(pkt.buf.front()->data()),
              pkt.buf.front()->length());
        }
        if (seenPeers.size() >= 2) {
          sock.getEventBase()->terminateLoopSoon();
        }
      });

  recvSock->resumeRead(&readCb);
  fEvb.loopForever();

  ASSERT_EQ(seenPeers.size(), 2u);
  ASSERT_EQ(seenPayloads.size(), 2u);
  // recvmmsg may return packets in either order; check by payload→peer pairing.
  for (size_t i = 0; i < seenPeers.size(); ++i) {
    if (seenPayloads[i] == "from-sender-1") {
      EXPECT_EQ(seenPeers[i], sender1Addr);
    } else if (seenPayloads[i] == "from-sender-2") {
      EXPECT_EQ(seenPeers[i], sender2Addr);
    } else {
      FAIL() << "unexpected payload: " << seenPayloads[i];
    }
  }
}
