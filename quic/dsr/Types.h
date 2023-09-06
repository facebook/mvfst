/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <folly/SocketAddress.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/Types.h>
#include <quic/server/state/ServerStateMachine.h>
#include <quic/state/StateData.h>

namespace quic {

// TODO: I don't think i need client address here.
struct ConnKey {
  ConnectionId scid;
  ConnectionId dcid;
};

struct ConnKeyHash {
  std::size_t operator()(const ConnKey& key) const {
    return folly::hash::hash_combine(
        ConnectionIdHash()(key.scid), ConnectionIdHash()(key.dcid));
  }
};

struct ConnKeyEq {
  bool operator()(const ConnKey& first, const ConnKey& second) const {
    return first.scid == second.scid && first.dcid == second.dcid;
  }
};

/**
 * The SendInstruction that frontend sends to backend to build a short-header
 * QUIC packet that contains a single Stream Frame.
 *
 * For now, a DSR packet will only have one stream frame, and nothing else. So
 * we are always gonna omit the Length field in the stream frame.
 *
 * TODO: Consider adding the type field here so that backend doesn't have to
 * to calculate it.
 *
 * TODO: We can also send over the encoded QuicInteger of some of these values.
 * Then the backends do not have to encode them again.
 *
 * TODO: Or even better: why don't I just send over the encoded short header
 * and stream fields as well as the meta info?
 */

struct SendInstruction {
  explicit SendInstruction(const SendInstruction& other)
      : dcid(other.dcid),
        scid(other.scid),
        clientAddress(other.clientAddress),
        packetNum(other.packetNum),
        largestAckedPacketNum(other.largestAckedPacketNum),
        writeOffset(other.writeOffset),
        largestAckedStreamOffset(other.largestAckedStreamOffset),
        streamId(other.streamId),
        streamOffset(other.streamOffset),
        len(other.len),
        fin(other.fin),
        bufMetaStartingOffset(other.bufMetaStartingOffset) {}

  explicit SendInstruction(SendInstruction&& other)
      : dcid(other.dcid),
        scid(other.scid),
        clientAddress(other.clientAddress),
        packetNum(other.packetNum),
        largestAckedPacketNum(other.largestAckedPacketNum),
        writeOffset(other.writeOffset),
        largestAckedStreamOffset(other.largestAckedStreamOffset),
        streamId(other.streamId),
        streamOffset(other.streamOffset),
        len(other.len),
        fin(other.fin),
        bufMetaStartingOffset(other.bufMetaStartingOffset) {}

  // Connection info:
  const ConnectionId& dcid;
  const ConnectionId& scid;
  const folly::SocketAddress& clientAddress;
  PacketNum packetNum{0};
  PacketNum largestAckedPacketNum{0};
  std::chrono::microseconds writeOffset{0us};

  // QUIC Stream info
  folly::Optional<uint64_t> largestAckedStreamOffset;
  StreamId streamId;
  uint64_t streamOffset;
  uint64_t len;
  bool fin;
  uint64_t bufMetaStartingOffset;

  struct Builder {
    explicit Builder(const QuicServerConnectionState& conn, StreamId idIn)
        : dcid(*conn.clientConnectionId),
          scid(*conn.serverConnectionId),
          clientAddr(conn.peerAddress),
          streamId(idIn) {}

    SendInstruction build() {
      return SendInstruction(
          dcid,
          scid,
          clientAddr,
          packetNum,
          largestAckedPacketNum,
          writeOffset,
          largestAckedStreamOffset,
          streamId,
          *streamOffset,
          *len,
          fin,
          *bufMetaStartingOffset);
    }

    Builder& setPacketNum(PacketNum val) {
      packetNum = val;
      return *this;
    }

    Builder& setLargestAckedPacketNum(PacketNum val) {
      largestAckedPacketNum = val;
      return *this;
    }

    Builder& setWriteOffset(std::chrono::microseconds val) {
      writeOffset = val;
      return *this;
    }

    Builder& setLargestAckedStreamOffset(uint64_t val) {
      largestAckedStreamOffset = val;
      return *this;
    }

    Builder& setStreamOffset(uint64_t val) {
      streamOffset = val;
      return *this;
    }

    Builder& setLength(uint64_t val) {
      len = val;
      return *this;
    }

    Builder& setFin(bool val) {
      fin = val;
      return *this;
    }

    Builder& setBufMetaStartingOffset(uint64_t val) {
      bufMetaStartingOffset = val;
      return *this;
    }

   private:
    const ConnectionId& dcid;
    const ConnectionId& scid;
    const folly::SocketAddress& clientAddr;
    PacketNum packetNum{0};
    PacketNum largestAckedPacketNum{0};
    folly::Optional<uint64_t> largestAckedStreamOffset;
    std::chrono::microseconds writeOffset{0us};
    StreamId streamId;
    folly::Optional<uint64_t> streamOffset;
    folly::Optional<uint64_t> len;
    bool fin{false};
    folly::Optional<uint64_t> bufMetaStartingOffset;
  };

 private:
  SendInstruction(
      const ConnectionId& dcidIn,
      const ConnectionId& scidIn,
      const folly::SocketAddress& clientAddrIn,
      PacketNum packetNumIn,
      PacketNum largestAckedPacketNumIn,
      std::chrono::microseconds writeOffsetIn,
      folly::Optional<uint64_t> largestAckedStreamOffsetIn,
      StreamId idIn,
      uint64_t streamOffsetIn,
      uint64_t lenIn,
      bool finIn,
      uint64_t bufMetaStartingOffsetIn)
      : dcid(dcidIn),
        scid(scidIn),
        clientAddress(clientAddrIn),
        packetNum(packetNumIn),
        largestAckedPacketNum(largestAckedPacketNumIn),
        writeOffset(writeOffsetIn),
        largestAckedStreamOffset(largestAckedStreamOffsetIn),
        streamId(idIn),
        streamOffset(streamOffsetIn),
        len(lenIn),
        fin(finIn),
        bufMetaStartingOffset(bufMetaStartingOffsetIn) {}
};

WriteStreamFrame sendInstructionToWriteStreamFrame(
    const SendInstruction& sendInstruction,
    uint64_t streamPacketIdx);

} // namespace quic
