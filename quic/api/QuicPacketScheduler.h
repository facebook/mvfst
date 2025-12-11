/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <boost/iterator/iterator_facade.hpp>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/api/QuicAckScheduler.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicPacketRebuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>

#include <folly/lang/Assume.h>

namespace quic {

struct SchedulingResult {
  Optional<ClonedPacketIdentifier> clonedPacketIdentifier;
  Optional<PacketBuilderInterface::Packet> packet;
  size_t shortHeaderPadding;

  explicit SchedulingResult(
      Optional<ClonedPacketIdentifier> clonedPacketIdentifierIn,
      Optional<PacketBuilderInterface::Packet> packetIn,
      size_t shortHeaderPaddingIn = 0)
      : clonedPacketIdentifier(std::move(clonedPacketIdentifierIn)),
        packet(std::move(packetIn)),
        shortHeaderPadding(shortHeaderPaddingIn) {}
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
   * a pair of ClonedPacketIdentifier and the Packet that was built.
   *
   * Returns an optional ClonedPacketIdentifier which indicates if the built out
   * packet is a clone and the associated ClonedPacketIdentifier for both origin
   * and clone.
   */
  [[nodiscard]] virtual quic::Expected<SchedulingResult, QuicError>
  scheduleFramesForPacket(
      PacketBuilderInterface&& builder,
      uint32_t writableBytes) = 0;

  /**
   * Returns whether the scheduler has data to send.
   */
  virtual bool hasData() const = 0;

  /**
   * Returns the name of the scheduler.
   */
  virtual folly::StringPiece name() const = 0;
};

class StreamFrameScheduler {
 public:
  explicit StreamFrameScheduler(QuicConnectionStateBase& conn);

  /**
   * Return: the first boolean indicates if at least one Blocked frame
   * is written into the packet by writeStreams function.
   */
  [[nodiscard]] quic::Expected<void, QuicError> writeStreams(
      PacketBuilderInterface& builder);

  bool hasPendingData() const;

 private:
  // Return true if this stream wrote some data
  [[nodiscard]] quic::Expected<bool, QuicError> writeStreamLossBuffers(
      PacketBuilderInterface& builder,
      QuicStreamState& stream);

  /**
   * Writes a single stream's write buffer or loss buffer.
   *
   * @param builder: The packet builder used to construct the packet.
   * @param stream: The state of the QUIC stream being written.
   * @param connWritableBytes: The number of writable bytes available in the
   *                           connection. It can be 0 and still write loss data
   *                           or stream FIN.  Mutated by this function
   *
   * Return: StreamWriteResult indicating whether the packet is full, connection
   * flow control limited, or not limited by connection flow control.
   */
  enum class StreamWriteResult { PACKET_FULL, NOT_LIMITED, CONN_FC_LIMITED };
  [[nodiscard]] quic::Expected<StreamWriteResult, QuicError> writeSingleStream(
      PacketBuilderInterface& builder,
      QuicStreamState& stream,
      uint64_t& connWritableBytes);

  [[nodiscard]] quic::Expected<StreamId, QuicError> writeStreamsHelper(
      PacketBuilderInterface& builder,
      const std::set<StreamId>& writableStreams,
      StreamId nextScheduledStream,
      uint64_t& connWritableBytes,
      bool streamPerPacket);

  [[nodiscard]] quic::Expected<void, QuicError> writeStreamsHelper(
      PacketBuilderInterface& builder,
      PriorityQueue& writableStreams,
      uint64_t& connWritableBytes,
      bool streamPerPacket);

  /**
   * Helper function to write either stream data if stream is not flow
   * controlled or a blocked frame otherwise.
   *
   * Return: A boolean indicates if write is successful.
   */
  [[nodiscard]] quic::Expected<bool, QuicError> writeStreamFrame(
      PacketBuilderInterface& builder,
      QuicStreamState& stream,
      uint64_t& connWritableBytes);

  QuicConnectionStateBase& conn_;
};

class RstStreamScheduler {
 public:
  explicit RstStreamScheduler(const QuicConnectionStateBase& conn);

  bool hasPendingRsts() const;

  [[nodiscard]] quic::Expected<bool, QuicError> writeRsts(
      PacketBuilderInterface& builder);

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

/*
 * PathValidationFrameScheduler schedules PathChallenge and PathResponse frames
 * for a specific path. This is used for writing packets on a path that is
 * not currently in use by the connection.
 * Note: For the current path, SimpleFrameScheduler schedules these frames.
 */
class PathValidationFrameScheduler {
 public:
  explicit PathValidationFrameScheduler(
      const QuicConnectionStateBase& conn,
      PathIdType pathId);

  [[nodiscard]] bool hasPendingPathValidationFrames() const;

  bool writePathValidationFrames(PacketBuilderInterface& builder);

 private:
  const QuicConnectionStateBase& conn_;
  const PathIdType pathId_;
};

class PingFrameScheduler {
 public:
  explicit PingFrameScheduler(const QuicConnectionStateBase& conn);

  bool hasPingFrame() const;

  bool writePing(PacketBuilderInterface& builder);

 private:
  const QuicConnectionStateBase& conn_;
};

class DatagramFrameScheduler {
 public:
  explicit DatagramFrameScheduler(QuicConnectionStateBase& conn);

  [[nodiscard]] bool hasPendingDatagramFrames() const;

  [[nodiscard]] quic::Expected<bool, QuicError> writeDatagramFrames(
      PacketBuilderInterface& builder);

 private:
  QuicConnectionStateBase& conn_;
};

class WindowUpdateScheduler {
 public:
  explicit WindowUpdateScheduler(const QuicConnectionStateBase& conn);

  bool hasPendingWindowUpdates() const;

  [[nodiscard]] quic::Expected<void, QuicError> writeWindowUpdates(
      PacketBuilderInterface& builder);

 private:
  const QuicConnectionStateBase& conn_;
};

class BlockedScheduler {
 public:
  explicit BlockedScheduler(const QuicConnectionStateBase& conn);

  bool hasPendingBlockedFrames() const;

  [[nodiscard]] quic::Expected<void, QuicError> writeBlockedFrames(
      PacketBuilderInterface& builder);

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
  [[nodiscard]] quic::Expected<bool, QuicError> writeCryptoData(
      PacketBuilderInterface& builder);

  bool hasData() const;

  folly::StringPiece name() const {
    return "CryptoScheduler";
  }

 private:
  const QuicConnectionStateBase& conn_;
  const QuicCryptoStream& cryptoStream_;
};

class ImmediateAckFrameScheduler {
 public:
  explicit ImmediateAckFrameScheduler(const QuicConnectionStateBase& conn);

  [[nodiscard]] bool hasPendingImmediateAckFrame() const;

  bool writeImmediateAckFrame(PacketBuilderInterface& builder);

 private:
  const QuicConnectionStateBase& conn_;
};

class FrameScheduler : public QuicPacketScheduler {
 public:
  ~FrameScheduler() override = default;

  struct Builder {
    Builder(
        QuicConnectionStateBase& conn,
        EncryptionLevel encryptionLevel,
        PacketNumberSpace packetNumberSpace,
        folly::StringPiece name);

    Builder& streamFrames();
    Builder& ackFrames();
    Builder& resetFrames();
    Builder& windowUpdateFrames();
    Builder& blockedFrames();
    Builder& cryptoFrames();
    Builder& simpleFrames();
    Builder& pingFrames();
    Builder& datagramFrames();
    Builder& immediateAckFrames();
    Builder& pathValidationFrames(PathIdType pathId);

    FrameScheduler build() &&;

   private:
    QuicConnectionStateBase& conn_;
    EncryptionLevel encryptionLevel_;
    PacketNumberSpace packetNumberSpace_;
    folly::StringPiece name_;

    // schedulers
    bool streamFrameScheduler_{false};
    bool ackScheduler_{false};
    bool rstScheduler_{false};
    bool windowUpdateScheduler_{false};
    bool blockedScheduler_{false};
    bool cryptoStreamScheduler_{false};
    bool simpleFrameScheduler_{false};
    bool pingFrameScheduler_{false};
    bool datagramFrameScheduler_{false};
    bool immediateAckFrameScheduler_{false};
    Optional<PathIdType> schedulePathValidationFramesForPathId_;
  };

  FrameScheduler(folly::StringPiece name, QuicConnectionStateBase& conn);

  [[nodiscard]] quic::Expected<SchedulingResult, QuicError>
  scheduleFramesForPacket(
      PacketBuilderInterface&& builder,
      uint32_t writableBytes) override;

  // If any scheduler, including AckScheduler, has pending data to send
  [[nodiscard]] bool hasData() const override;

  // If AckScheduler has any pending acks to write.
  [[nodiscard]] bool hasPendingAcks() const;

  // If any of the non-Ack scheduler has pending data to send
  [[nodiscard]] virtual bool hasImmediateData() const;

  [[nodiscard]] folly::StringPiece name() const override;

 private:
  Optional<StreamFrameScheduler> streamFrameScheduler_;
  Optional<AckScheduler> ackScheduler_;
  Optional<RstStreamScheduler> rstScheduler_;
  Optional<WindowUpdateScheduler> windowUpdateScheduler_;
  Optional<BlockedScheduler> blockedScheduler_;
  Optional<CryptoStreamScheduler> cryptoStreamScheduler_;
  Optional<SimpleFrameScheduler> simpleFrameScheduler_;
  Optional<PingFrameScheduler> pingFrameScheduler_;
  Optional<DatagramFrameScheduler> datagramFrameScheduler_;
  Optional<ImmediateAckFrameScheduler> immediateAckFrameScheduler_;
  Optional<PathValidationFrameScheduler> pathValidationFrameScheduler_;
  folly::StringPiece name_;
  QuicConnectionStateBase& conn_;
};

/**
 * A packet scheduler wrapping a normal FrameScheduler with the ability to clone
 * exiting packets that are still outstanding. A CloningScheduler first tries to
 * write new frames with new data into a packet. If that fails due to the lack
 * of new data, it falls back to cloning one inflight packet from a connection's
 * outstanding packets if there is at least one outstanding packet that's
 * smaller than the writableBytes limit.
 */
class CloningScheduler : public QuicPacketScheduler {
 public:
  // Normally a scheduler takes in a const conn, and update conn later. But for
  // this one I want to update conn right inside this class itself.
  CloningScheduler(
      FrameScheduler& scheduler,
      QuicConnectionStateBase& conn,
      const folly::StringPiece name,
      uint64_t cipherOverhead);

  bool hasData() const override;

  /**
   * Returns a optional ClonedPacketIdentifier which indicates if the built out
   * packet is a clone and the associated ClonedPacketIdentifier for both origin
   * and clone.
   */
  [[nodiscard]] quic::Expected<SchedulingResult, QuicError>
  scheduleFramesForPacket(
      PacketBuilderInterface&& builder,
      uint32_t writableBytes) override;

  folly::StringPiece name() const override;

 private:
  FrameScheduler& frameScheduler_;
  QuicConnectionStateBase& conn_;
  folly::StringPiece name_;
  uint64_t cipherOverhead_;
};

} // namespace quic
