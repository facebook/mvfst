/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <boost/iterator/iterator_facade.hpp>
#include <folly/Overload.h>
#include <quic/QuicConstants.h>
#include <quic/QuicException.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/QuicWriteCodec.h>
#include <quic/codec/Types.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {

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
  virtual std::pair<
      folly::Optional<PacketEvent>,
      folly::Optional<RegularQuicPacketBuilder::Packet>>
  scheduleFramesForPacket(
      RegularQuicPacketBuilder&& builder,
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

// A tag to denote how we should schedule ack in this packet.
enum class AckMode { Pending, Immediate };

class RetransmissionScheduler {
 public:
  explicit RetransmissionScheduler(const QuicConnectionStateBase& conn);

  void writeRetransmissionStreams(PacketBuilderInterface& builder);

  bool hasPendingData() const;

 private:
  StreamFrameMetaData makeStreamFrameMetaDataFromStreamBufer(
      StreamId id,
      const StreamBuffer& buffer,
      bool moreFrames) const;
  const QuicConnectionStateBase& conn_;
};

class StreamFrameScheduler {
 public:
  explicit StreamFrameScheduler(const QuicConnectionStateBase& conn);

  /**
   * Return: the first boolean indicates if at least one Blocked frame
   * is written into the packet by writeStreams function.
   */
  void writeStreams(PacketBuilderInterface& builder);

  bool hasPendingData() const;

 private:
  /**
   * A helper iterator adaptor class that starts iteration of streams from a
   * specific stream id.
   */
  class MiddleStartingIterationWrapper {
   public:
    using MapType = std::set<StreamId>;

    class MiddleStartingIterator
        : public boost::iterator_facade<
              MiddleStartingIterator,
              const MiddleStartingIterationWrapper::MapType::value_type,
              boost::forward_traversal_tag> {
      friend class boost::iterator_core_access;

     public:
      using MapType = MiddleStartingIterationWrapper::MapType;

      MiddleStartingIterator() = default;

      MiddleStartingIterator(
          const MapType* streams,
          const MapType::key_type& start)
          : streams_(streams) {
        itr_ = streams_->lower_bound(start);
        checkForWrapAround();
      }

      const MapType::value_type& dereference() const {
        return *itr_;
      }

      bool equal(const MiddleStartingIterator& other) const {
        return wrappedAround_ == other.wrappedAround_ && itr_ == other.itr_;
      }

      void increment() {
        ++itr_;
        checkForWrapAround();
      }

      void checkForWrapAround() {
        if (itr_ == streams_->cend()) {
          wrappedAround_ = true;
          itr_ = streams_->cbegin();
        }
      }

     private:
      friend class MiddleStartingIterationWrapper;
      bool wrappedAround_{false};
      const MapType* streams_{nullptr};
      MapType::const_iterator itr_;
    };

    MiddleStartingIterationWrapper(
        const MapType& streams,
        const MapType::key_type& start)
        : streams_(streams), start_(start) {}

    MiddleStartingIterator cbegin() const {
      return MiddleStartingIterator(&streams_, start_);
    }

    MiddleStartingIterator cend() const {
      MiddleStartingIterator itr(&streams_, start_);
      itr.wrappedAround_ = true;
      return itr;
    }

   private:
    const MapType& streams_;
    const MapType::key_type& start_;
  };

  using WritableStreamItr =
      MiddleStartingIterationWrapper::MiddleStartingIterator;

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
      WritableStreamItr& writableStreamItr,
      uint64_t& connWritableBytes);

  StreamFrameMetaData makeStreamFrameMetaData(
      const QuicStreamState& streamData,
      bool hasMoreData,
      uint64_t connWritableBytes);

  const QuicConnectionStateBase& conn_;
};

class AckScheduler {
 public:
  AckScheduler(const QuicConnectionStateBase& conn, const AckState& ackState);

  template <typename ClockType = Clock>
  folly::Optional<PacketNum> writeNextAcks(
      PacketBuilderInterface& builder,
      AckMode mode);

  bool hasPendingAcks() const;

 private:
  /* Write out pending acks if needsToSendAckImmeidately in the connection's
   * pendingEvent is true.
   */
  template <typename ClockType>
  folly::Optional<PacketNum> writeAcksIfPending(
      PacketBuilderInterface& builder);

  // Write out pending acks
  template <typename ClockType>
  folly::Optional<PacketNum> writeAcksImpl(PacketBuilderInterface& builder);

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

  /**
   * Returns a optional PacketEvent which indicates if the built out packet is a
   * clone and the associated PacketEvent for both origin and clone. In the case
   * of CryptoStreamScheduler, this will always return folly::none.
   */
  std::pair<
      folly::Optional<PacketEvent>,
      folly::Optional<RegularQuicPacketBuilder::Packet>>
  scheduleFramesForPacket(
      RegularQuicPacketBuilder&& builder,
      uint32_t writableBytes);

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
        const QuicConnectionStateBase& conn,
        EncryptionLevel encryptionLevel,
        PacketNumberSpace packetNumberSpace,
        const std::string& name);

    Builder& streamRetransmissions();
    Builder& streamFrames();
    Builder& ackFrames();
    Builder& resetFrames();
    Builder& windowUpdateFrames();
    Builder& blockedFrames();
    Builder& cryptoFrames();
    Builder& simpleFrames();

    FrameScheduler build() &&;

   private:
    const QuicConnectionStateBase& conn_;
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
  };

  explicit FrameScheduler(const std::string& name);

  virtual std::pair<
      folly::Optional<PacketEvent>,
      folly::Optional<RegularQuicPacketBuilder::Packet>>
  scheduleFramesForPacket(
      RegularQuicPacketBuilder&& builder,
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
  std::pair<
      folly::Optional<PacketEvent>,
      folly::Optional<RegularQuicPacketBuilder::Packet>>
  scheduleFramesForPacket(
      RegularQuicPacketBuilder&& builder,
      uint32_t writableBytes) override;

  std::string name() const override;

 private:
  FrameScheduler& frameScheduler_;
  QuicConnectionStateBase& conn_;
  std::string name_;
  uint64_t cipherOverhead_;
};
} // namespace quic
#include <quic/api/QuicPacketScheduler-inl.h>
