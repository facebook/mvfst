// (c) Facebook, Inc. and its affiliates. Confidential and proprietary.

// #include <folly/portability/GMock.h>
// #include <folly/portability/GTest.h>

#include <quic/api/QuicTransportBase.h>
#include <quic/common/test/TestUtils.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/StateData.h>

namespace quic::test {

template <typename QuicTransportTestClass>
class QuicTypedTransportTestBase : protected QuicTransportTestClass {
 public:
  using QuicTransportTestClass::QuicTransportTestClass;

  ~QuicTypedTransportTestBase() override = default;

  void SetUp() override {
    QuicTransportTestClass::SetUp();
  }

  QuicTransportBase* getTransport() {
    return QuicTransportTestClass::getTransport();
  }

  const QuicConnectionStateBase& getConn() {
    return QuicTransportTestClass::getConn();
  }

  QuicConnectionStateBase& getNonConstConn() {
    return QuicTransportTestClass::getNonConstConn();
  }

  struct NewOutstandingPacketInterval {
    const PacketNum start;
    const PacketNum end;
  };

  /**
   * Provide transport with opportunity to write packets.
   *
   * If new AppData packets written, returns packet numbers in interval.
   *
   * @return    Interval of newly written AppData packet numbers, or none.
   */
  folly::Optional<NewOutstandingPacketInterval> loopForWrites() {
    // store the next packet number
    const auto preSendNextAppDataPacketNum =
        getNextPacketNum(getConn(), PacketNumberSpace::AppData);

    // loop to trigger writes
    QuicTransportTestClass::loopForWrites();

    // if we cannot find an outstanding AppData packet, we sent nothing new.
    //
    // we include "lost" to protect against the unusual case of the test somehow
    // causing a packet that was just written to be immediately marked lost.
    const auto it = quic::getLastOutstandingPacketIncludingLost(
        getNonConstConn(), PacketNumberSpace::AppData);
    if (it == getConn().outstandings.packets.rend()) {
      return folly::none;
    }
    const auto& packet = it->packet;
    const auto lastAppDataPacketNum = packet.header.getPacketSequenceNum();

    // if packet number of last AppData packet < nextAppDataPacketNum, then
    // we sent nothing new and we have nothing to do...
    if (lastAppDataPacketNum < preSendNextAppDataPacketNum) {
      return folly::none;
    }

    // we sent new AppData packets
    return NewOutstandingPacketInterval{
        preSendNextAppDataPacketNum, lastAppDataPacketNum};
  }

  /**
   * Deliver a single packet from the remote.
   */
  void deliverPacket(
      Buf&& buf,
      quic::TimePoint recvTime = TimePoint::clock::now()) {
    QuicTransportTestClass::deliverData(NetworkData(std::move(buf), recvTime));
  }

  /**
   * Build a packet with ACK frame for previously sent AppData packets.
   */
  quic::Buf buildAckPacketForSentAppDataPackets(quic::AckBlocks acks) {
    auto buf = quic::test::packetToBuf(quic::test::createAckPacket(
        getNonConstConn(),
        ++peerNextAppDataPacketNum,
        acks,
        quic::PacketNumberSpace::AppData));
    buf->coalesce();
    return buf;
  }

  /**
   * Build a packet with ACK frame for previously sent AppData packets.
   */
  quic::Buf buildAckPacketForSentAppDataPackets(
      quic::PacketNum intervalStart,
      quic::PacketNum intervalEnd) {
    quic::AckBlocks acks = {{intervalStart, intervalEnd}};
    return buildAckPacketForSentAppDataPackets(acks);
  }

  /**
   * Get next acceptable local (self) bidirectional stream number.
   */
  StreamId getNextLocalBidirectionalStreamId() {
    const auto maybeStreamId =
        getConn().streamManager->getNextLocalBidirectionalStreamId().value();
    CHECK(maybeStreamId.has_value());
    return maybeStreamId.value();
  }

  /**
   * Get next acceptable local (self) unidirectional stream number.
   */
  StreamId getNextLocalUnidirectionalStreamId() {
    const auto maybeStreamId =
        getConn().streamManager->getNextLocalUnidirectionalStreamId().value();
    CHECK(maybeStreamId.has_value());
    return maybeStreamId.value();
  }

  /**
   * Get next acceptable remote (peer) bidirectional stream number.
   */
  StreamId getNextPeerBidirectionalStreamId() {
    const auto maybeStreamId =
        getConn().streamManager->getNextPeerBidirectionalStreamId().value();
    CHECK(maybeStreamId.has_value());
    return maybeStreamId.value();
  }

  /**
   * Get next acceptable remote (peer) unidirectional stream number.
   */
  StreamId getNextPeerUnidirectionalStreamId() {
    const auto maybeStreamId =
        getConn().streamManager->getNextPeerUnidirectionalStreamId().value();
    CHECK(maybeStreamId.has_value());
    return maybeStreamId.value();
  }

  quic::PacketNum peerNextAppDataPacketNum{0};
};

} // namespace quic::test
