/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/backend/openssl/OpenSSLFactory.h>
#include <fizz/crypto/aead/Aead.h>
#include <fizz/protocol/Factory.h>
#include <fizz/protocol/Protocol.h>
#include <fizz/record/Types.h>
#include <folly/Hash.h>
#include <folly/SocketAddress.h>
#include <folly/container/EvictingCacheMap.h>
#include <folly/io/async/AsyncUDPSocket.h>
#include <quic/api/IoBufQuicBatch.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/codec/QuicConnectionId.h>
#include <quic/codec/QuicPacketBuilder.h>
#include <quic/codec/Types.h>
#include <quic/dsr/Types.h>
#include <quic/fizz/handshake/FizzBridge.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/handshake/Aead.h>
#include <quic/xsk/BaseXskContainer.h>

namespace quic {

/**
 * For now, each packetization request builds only one QUIC packet. I think
 * it's easier to batch packetization requests than to make one request build
 * multiple packets. But I'm open to discussion.
 *
 * What a Packetization request is supposed to include:
 *
 * All parems in CipherBuilder::buildCiphers():
 *    TrafficKey (key + iv), CipherSuite, packet protection key
 *
 * Then all the non-cipher params in DSRBackenderSender::sendQuicPacket:
 *    DCID, Client addr, Packet Number, Stream Id, Stream offset, Stream data
 *    length, Stream data EOF.
 *
 */

struct CipherPair {
  std::unique_ptr<Aead> aead;
  std::unique_ptr<PacketNumberCipher> headerCipher;
};

class CipherBuilder {
 public:
  CipherPair buildCiphers(
      fizz::TrafficKey&& trafficKey,
      fizz::CipherSuite cipherSuite,
      std::unique_ptr<folly::IOBuf> packetProtectionKey) {
    auto aead = FizzAead::wrap(deriveRecordAeadWithLabel(
        *quicFizzCryptoFactory_.getFizzFactory(),
        std::move(trafficKey),
        cipherSuite));
    auto headerCipher = quicFizzCryptoFactory_.makePacketNumberCipher(
        fizz::CipherSuite::TLS_AES_128_GCM_SHA256);
    headerCipher->setKey(packetProtectionKey->coalesce());

    return {std::move(aead), std::move(headerCipher)};
  }

 private:
  std::unique_ptr<fizz::Aead> deriveRecordAeadWithLabel(
      const fizz::Factory& factory,
      fizz::TrafficKey trafficKey,
      fizz::CipherSuite cipher) {
    auto aead = factory.makeAead(cipher);
    aead->setKey(std::move(trafficKey));
    return aead;
  }

  FizzCryptoFactory quicFizzCryptoFactory_;
};

class QuicPacketizer {
 public:
  virtual ~QuicPacketizer() = default;

  virtual std::unique_ptr<folly::IOBuf> sendQuicPacket(
      ConnectionId dcid,
      const folly::SocketAddress& clientAddr,
      PacketNum packetNum,
      const Aead& aead,
      const PacketNumberCipher& headerCipher,
      StreamId streamId,
      size_t offset,
      size_t length,
      bool eof) = 0;
};

struct PacketizationRequest {
  PacketizationRequest(
      PacketNum packetNumIn,
      PacketNum largestAckedPacketNumIn,
      StreamId streamIdIn,
      uint64_t offsetIn,
      uint64_t lenIn,
      bool finIn,
      uint64_t payloadOffsetIn)
      : packetNum(packetNumIn),
        largestAckedPacketNum(largestAckedPacketNumIn),
        streamId(streamIdIn),
        offset(offsetIn),
        len(lenIn),
        fin(finIn),
        payloadOffset(payloadOffsetIn) {}
  PacketNum packetNum;
  PacketNum largestAckedPacketNum;

  // QUIC Stream info
  StreamId streamId;
  uint64_t offset;
  uint64_t len;
  bool fin;
  // This is the offset of the buffer payload. It is different from the offset
  // above which is the stream bytes offset.
  uint64_t payloadOffset;
};

struct RequestGroup {
  ConnectionId dcid;
  ConnectionId scid;
  folly::SocketAddress clientAddress;
  const CipherPair* cipherPair{nullptr};
  SmallVec<PacketizationRequest, 64> requests;
  std::chrono::microseconds writeOffset{0us};
};

class PacketGroupWriter {
 public:
  virtual ~PacketGroupWriter() = default;

  BufQuicBatchResult writePacketsGroup(
      RequestGroup& reqGroup,
      const std::function<Buf(const PacketizationRequest& req)>& bufProvider);

  bool writeSingleQuicPacket(
      BufAccessor& accessor,
      ConnectionId dcid,
      PacketNum packetNum,
      PacketNum largestAckedByPeer,
      const Aead& aead,
      const PacketNumberCipher& headerCipher,
      StreamId streamId,
      size_t offset,
      size_t length,
      bool eof,
      Buf buf);

 protected:
  uint32_t prevSize_{0};

 private:
  virtual void flush() = 0;

  virtual BufAccessor* getBufAccessor() = 0;

  virtual void rollback() = 0;

  virtual bool send(uint32_t size) = 0;

  virtual BufQuicBatchResult getResult() = 0;
};

class UdpSocketPacketGroupWriter : public PacketGroupWriter {
 public:
  // This constructor is for testing only.
  UdpSocketPacketGroupWriter(
      QuicAsyncUDPSocket& sock,
      const folly::SocketAddress& clientAddress,
      BatchWriterPtr&& batchWriter);

  UdpSocketPacketGroupWriter(
      QuicAsyncUDPSocket& sock,
      const folly::SocketAddress& clientAddress);

  ~UdpSocketPacketGroupWriter() override = default;

  IOBufQuicBatch& getIOBufQuicBatch() {
    return ioBufBatch_;
  }

 private:
  void flush() override;

  BufAccessor* getBufAccessor() override;

  void rollback() override;

  bool send(uint32_t size) override;

  BufQuicBatchResult getResult() override;

  QuicAsyncUDPSocket& sock_;
  quic::QuicConnectionStateBase& fakeConn_;
  IOBufQuicBatch ioBufBatch_;
  BufQuicBatchResult result_;
};

#if defined(__linux__)

class XskPacketGroupWriter : public PacketGroupWriter {
 public:
  XskPacketGroupWriter(
      facebook::xdpsocket::XskSender* xskSender,
      folly::SocketAddress clientAddress,
      folly::SocketAddress vipAddress)
      : xskSender_(xskSender),
        clientAddress_(std::move(clientAddress)),
        vipAddress_(std::move(vipAddress)) {}

  ~XskPacketGroupWriter() override = default;

 private:
  void flush() override;

  BufAccessor* getBufAccessor() override;

  void rollback() override;

  bool send(uint32_t size) override;

  BufQuicBatchResult getResult() override;

  facebook::xdpsocket::XskSender* xskSender_;
  folly::SocketAddress clientAddress_;
  folly::SocketAddress vipAddress_;
  facebook::xdpsocket::XskBuffer currentXskBuffer_;
  BufQuicBatchResult result_;
  std::unique_ptr<SimpleBufAccessor> bufAccessor_;
};

#endif

} // namespace quic
