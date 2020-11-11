/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <boost/iterator/iterator_facade.hpp>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

struct SchedulingResult {
  folly::Optional<PacketEvent> packetEvent;
  folly::Optional<PacketBuilderInterface::Packet> packet;

  explicit SchedulingResult(
      folly::Optional<PacketEvent> packetEventIn,
      folly::Optional<PacketBuilderInterface::Packet> packetIn)
      : packetEvent(std::move(packetEventIn)), packet(std::move(packetIn)) {}
};

/**
 * Common interface for Quic packet schedulers
 * used at the top level.
 */
class QuicPacketScheduler {
 public:
  virtual ~QuicPacketScheduler() = default;

  /**
   * Schedules frames and writes them to the builder and returns
   * a pair of PacketEvent and the Packet that was built.
   *
   * Returns an optional PacketEvent which indicates if the built out packet is
   * a clone and the associated PacketEvent for both origin and clone.
   */
  virtual SchedulingResult scheduleFramesForPacket(
      PacketBuilderInterface&& builder,
      uint32_t writableBytes) = 0;

  /**
   * Returns whether the scheduler has data to send.
   */
  virtual bool hasData() const = 0;

  /**
   * Returns the name of the scheduler.
   */
  virtual std::string name() const = 0;
};

class RetransmissionScheduler {
 public:
  explicit RetransmissionScheduler(const QuicConnectionStateBase& conn);

  void writeRetransmissionStreams(PacketBuilderInterface& builder);

  bool hasPendingData() const;

 private:
  bool writeStreamLossBuffers(PacketBuilderInterface& builder, StreamId id);

  const QuicConnectionStateBase& conn_;
};

class StreamFrameScheduler {
 public:
  explicit StreamFrameScheduler(QuicConnectionStateBase& conn);

  /**
   * Return: the first boolean indicates if at least one Blocked frame
   * is written into the packet by writeStreams function.
   */
  void writeStreams(PacketBuilderInterface& builder);

  bool hasPendingData() const;

 private:
  StreamId writeStreamsHelper(
      PacketBuilderInterface& builder,
      const std::set<StreamId>& writableStreams,
      StreamId nextScheduledStream,
      uint64_t& connWritableBytes,
      bool streamPerPacket);

  void writeStreamsHelper(
      PacketBuilderInterface& builder,
      PriorityQueue& writableStreams,
      uint64_t& connWritableBytes,
      bool streamPerPacket);

  /**
   * Helper function to write either stream data if stream is not flow
   * controlled or a blocked frame otherwise.
   *
   * Return: boolean indicates if anything (either data, or Blocked frame) is
   *   written into the packet.
   *
   */
  bool writeNextStreamFrame(
      PacketBuilderInterface& builder,
      StreamId streamId,
      uint64_t& connWritableBytes);

  QuicConnectionStateBase& conn_;
};

class AckScheduler {
 public:
  AckScheduler(const QuicConnectionStateBase& conn, const AckState& ackState);

  template <typename ClockType = Clock>
  folly::Optional<PacketNum> writeNextAcks(PacketBuilderInterface& builder);

  bool hasPendingAcks() const;

 private:
  const QuicConnectionStateBase& conn_;
  const AckState& ackState_;
};

/**
 * Returns whether or not the Ack scheduler has acks to schedule. This does not
 * tell you when the ACKs can be written.
 */
bool hasAcksToSchedule(const AckState& ackState);

/**
 * Returns the largest packet received which needs to be acked.
 */
folly::Optional<PacketNum> largestAckToSend(const AckState& ackState);

class RstStreamScheduler {
 public:
  explicit RstStreamScheduler(const QuicConnectionStateBase& conn);

  bool hasPendingRsts() const;

  bool writeRsts(PacketBuilderInterface& builder);

 private:
  const QuicConnectionStateBase& conn_;
};

/*
 * Simple frames are those whose mechanics are "simple" wrt the send/receive
 * mechanics. These frames are retransmitted regularly on loss.
 */
class SimpleFrameScheduler {
 public:
  explicit SimpleFrameScheduler(const QuicConnectionStateBase& conn);

  bool hasPendingSimpleFrames() const;

  bool writeSimpleFrames(PacketBuilderInterface& builder);

 private:
  const QuicConnectionStateBase& conn_;
};

class PingFrameScheduler {
 public:
  explicit PingFrameScheduler(const QuicConnectionStateBase& conn);

  bool hasPingFrame() const;

  bool writePing(PacketBuilderInterface& builder);

 private:
  const QuicConnectionStateBase& conn_;
};

class WindowUpdateScheduler {
 public:
  explicit WindowUpdateScheduler(const QuicConnectionStateBase& conn);

  bool hasPendingWindowUpdates() const;

  void writeWindowUpdates(PacketBuilderInterface& builder);

 private:
  const QuicConnectionStateBase& conn_;
};

class BlockedScheduler {
 public:
  explicit BlockedScheduler(const QuicConnectionStateBase& conn);

  bool hasPendingBlockedFrames() const;

  void writeBlockedFrames(PacketBuilderInterface& builder);

 private:
  const QuicConnectionStateBase& conn_;
};

class CryptoStreamScheduler {
 public:
  explicit CryptoStreamScheduler(
      const QuicConnectionStateBase& conn,
      const QuicCryptoStream& cryptoStream);

  /**
   * Returns whether or we could write data to the stream.
   */
  bool writeCryptoData(PacketBuilderInterface& builder);

  bool hasData() const;

  std::string name() const {
    return "CryptoScheduler";
  }

 private:
  const QuicConnectionStateBase& conn_;
  const QuicCryptoStream& cryptoStream_;
  std::string name_;
};

class FrameScheduler : public QuicPacketScheduler {
 public:
  ~FrameScheduler() override = default;

  struct Builder {
    Builder(
        QuicConnectionStateBase& conn,
        EncryptionLevel encryptionLevel,
        PacketNumberSpace packetNumberSpace,
        std::string name);

    Builder& streamRetransmissions();
    Builder& streamFrames();
    Builder& ackFrames();
    Builder& resetFrames();
    Builder& windowUpdateFrames();
    Builder& blockedFrames();
    Builder& cryptoFrames();
    Builder& simpleFrames();
    Builder& pingFrames();

    FrameScheduler build() &&;

   private:
    QuicConnectionStateBase& conn_;
    EncryptionLevel encryptionLevel_;
    PacketNumberSpace packetNumberSpace_;
    std::string name_;

    // schedulers
    bool retransmissionScheduler_{false};
    bool streamFrameScheduler_{false};
    bool ackScheduler_{false};
    bool rstScheduler_{false};
    bool windowUpdateScheduler_{false};
    bool blockedScheduler_{false};
    bool cryptoStreamScheduler_{false};
    bool simpleFrameScheduler_{false};
    bool pingFrameScheduler_{false};
  };

  explicit FrameScheduler(std::string name);

  SchedulingResult scheduleFramesForPacket(
      PacketBuilderInterface&& builder,
      uint32_t writableBytes) override;

  // If any scheduler, including AckScheduler, has pending data to send
  virtual bool hasData() const override;

  // If any of the non-Ack scheduler has pending data to send
  virtual bool hasImmediateData() const;

  virtual std::string name() const override;

 private:
  folly::Optional<RetransmissionScheduler> retransmissionScheduler_;
  folly::Optional<StreamFrameScheduler> streamFrameScheduler_;
  folly::Optional<AckScheduler> ackScheduler_;
  folly::Optional<RstStreamScheduler> rstScheduler_;
  folly::Optional<WindowUpdateScheduler> windowUpdateScheduler_;
  folly::Optional<BlockedScheduler> blockedScheduler_;
  folly::Optional<CryptoStreamScheduler> cryptoStreamScheduler_;
  folly::Optional<SimpleFrameScheduler> simpleFrameScheduler_;
  folly::Optional<PingFrameScheduler> pingFrameScheduler_;
  std::string name_;
};

/**
 * A packet scheduler wrapping a normal FrameScheduler with the ability to clone
 * exiting packets that are still outstanding. A CloningScheduler first trie to
 * write new farmes with new data into a packet. If that fails due to the lack
 * of new data, it falls back to cloning one inflight packet from a connection's
 * oustanding packets if there is at least one outstanding packet that's smaller
 * than the writableBytes limit, and isn't a Handshake packet.
 */
class CloningScheduler : public QuicPacketScheduler {
 public:
  // Normally a scheduler takes in a const conn, and update conn later. But for
  // this one I want to update conn right inside this class itself.
  // TODO: Passing cipherOverhead into the CloningScheduler to recalculate the
  // correct writableBytes isn't ideal. But unblock me or others from quickly
  // testing it on load test. :(
  CloningScheduler(
      FrameScheduler& scheduler,
      QuicConnectionStateBase& conn,
      const std::string& name,
      uint64_t cipherOverhead);

  bool hasData() const override;

  /**
   * Returns a optional PacketEvent which indicates if the built out packet is a
   * clone and the associated PacketEvent for both origin and clone.
   */
  SchedulingResult scheduleFramesForPacket(
      PacketBuilderInterface&& builder,
      uint32_t writableBytes) override;

  std::string name() const override;

 private:
  FrameScheduler& frameScheduler_;
  QuicConnectionStateBase& conn_;
  std::string name_;
  uint64_t cipherOverhead_;
};

/**
 * This is the packet scheduler for D6D probe packets. It only schedule a PING
 * frame followed by many PADDING frames, forming a probeSize-sized packet.
 */
class D6DProbeScheduler : public QuicPacketScheduler {
 public:
  D6DProbeScheduler(
      QuicConnectionStateBase& conn,
      std::string name,
      uint64_t cipherOverhead,
      uint32_t probSize);

  FOLLY_NODISCARD bool hasData() const override;

  SchedulingResult scheduleFramesForPacket(
      PacketBuilderInterface&& builder,
      uint32_t writableBytes) override;

  FOLLY_NODISCARD std::string name() const override;

 private:
  QuicConnectionStateBase& conn_;
  std::string name_;
  uint64_t cipherOverhead_;
  uint32_t probeSize_;
  bool probeSent_{false};
};
} // namespace quic
#include <quic/api/QuicPacketScheduler-inl.h>
