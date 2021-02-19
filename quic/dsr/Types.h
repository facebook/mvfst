/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <fizz/crypto/aead/Aead.h>
#include <fizz/record/Types.h>
#include <folly/SocketAddress.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/Types.h>
#include <optional>

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
  // Connection info:
  // TODO: All these are not correctly set right now
  std::optional<ConnKey> connKey;
  folly::SocketAddress clientAddress;
  PacketNum packetNum{0};
  PacketNum largestAckedPacketNum{0};

  // QUIC Stream info
  StreamId streamId;
  uint64_t offset;
  uint64_t len;
  bool fin;
  // The starting offset of the first BufferMeta byte in this stream.
  // TODO: This isn't set correctly right now
  uint64_t bufMetaStartingOffset{0};

  // Cipher info
  // TODO: All these are not correctly set right now
  fizz::TrafficKey trafficKey;
  fizz::CipherSuite cipherSuite;
  std::unique_ptr<folly::IOBuf> packetProtectionKey;

  struct Builder {
    explicit Builder(StreamId idIn) : streamId(idIn) {}

    SendInstruction build() {
      return SendInstruction(streamId, *offset, *len, fin);
    }

    Builder& setOffset(uint64_t val) {
      offset = val;
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

   private:
    StreamId streamId;
    std::optional<uint64_t> offset;
    std::optional<uint64_t> len;
    bool fin{false};
  };

 private:
  SendInstruction(StreamId idIn, uint64_t offsetIn, uint64_t lenIn, bool finIn)
      : streamId(idIn), offset(offsetIn), len(lenIn), fin(finIn) {}
};

} // namespace quic
