/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <quic/codec/Decode.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/codec/Types.h>
#include <quic/common/BufUtil.h>
#include <quic/handshake/Aead.h>
#include <quic/state/AckStates.h>

namespace quic {

/**
 * Structure which describes data which could not be processed by
 * the read codec due to the required cipher being unavailable. The caller might
 * use this to retry later once the cipher is available.
 */
struct CipherUnavailable {
  Buf packet;
  ProtectionType protectionType;

  CipherUnavailable(Buf packetIn, ProtectionType protectionTypeIn)
      : packet(std::move(packetIn)), protectionType(protectionTypeIn) {}
};

/**
 * A type which represents no data.
 */
struct Nothing {};

struct CodecResult {
  enum class Type {
    REGULAR_PACKET,
    RETRY,
    CIPHER_UNAVAILABLE,
    STATELESS_RESET,
    NOTHING
  };

  ~CodecResult();

  CodecResult(CodecResult&& other) noexcept;
  CodecResult& operator=(CodecResult&& other) noexcept;

  /* implicit */ CodecResult(RegularQuicPacket&& regularPacketIn);
  /* implicit */ CodecResult(CipherUnavailable&& cipherUnavailableIn);
  /* implicit */ CodecResult(StatelessReset&& statelessReset);
  /* implicit */ CodecResult(RetryPacket&& retryPacket);
  /* implicit */ CodecResult(Nothing&& nothing);

  Type type();
  RegularQuicPacket* regularPacket();
  CipherUnavailable* cipherUnavailable();
  StatelessReset* statelessReset();
  RetryPacket* retryPacket();
  Nothing* nothing();

 private:
  void destroyCodecResult();

  union {
    RegularQuicPacket packet;
    RetryPacket retry;
    CipherUnavailable cipher;
    StatelessReset reset;
    Nothing none;
  };

  Type type_;
};

/**
 * Reads given data and returns parsed long header.
 * Returns an error if parsing is unsuccessful.
 */
folly::Expected<ParsedLongHeader, TransportErrorCode> tryParseLongHeader(
    folly::io::Cursor& cursor,
    QuicNodeType nodeType);

class QuicReadCodec {
 public:
  virtual ~QuicReadCodec() = default;

  explicit QuicReadCodec(QuicNodeType nodeType);

  /**
   * Tries to parse a packet from the buffer data.
   * If it is able to parse the packet, then it returns
   * a valid QUIC packet. If it is not able to parse a packet it might return a
   * cipher unavailable structure. The caller can then retry when the cipher is
   * available. A client should call tryParsingVersionNegotiation
   * before the version is negotiated to detect VN.
   */
  virtual CodecResult parsePacket(
      BufQueue& queue,
      const AckStates& ackStates,
      size_t dstConnIdSize = kDefaultConnectionIdSize);

  /**
   * Tries to parse the packet and returns whether or not
   * it is a version negotiation packet.
   * This returns folly::none if the packet is either not
   * a VN packet or is invalid.
   */
  folly::Optional<VersionNegotiationPacket> tryParsingVersionNegotiation(
      BufQueue& queue);

  const Aead* getOneRttReadCipher() const;
  const Aead* getZeroRttReadCipher() const;
  const Aead* getHandshakeReadCipher() const;

  const Aead* getInitialCipher() const;

  const PacketNumberCipher* getInitialHeaderCipher() const;
  const PacketNumberCipher* getOneRttHeaderCipher() const;
  const PacketNumberCipher* getHandshakeHeaderCipher() const;
  const PacketNumberCipher* getZeroRttHeaderCipher() const;

  const folly::Optional<StatelessResetToken>& getStatelessResetToken() const;

  CodecParameters getCodecParameters() const;

  void setInitialReadCipher(std::unique_ptr<Aead> initialReadCipher);
  void setOneRttReadCipher(std::unique_ptr<Aead> oneRttReadCipher);
  void setZeroRttReadCipher(std::unique_ptr<Aead> zeroRttReadCipher);
  void setHandshakeReadCipher(std::unique_ptr<Aead> handshakeReadCipher);

  void setInitialHeaderCipher(
      std::unique_ptr<PacketNumberCipher> initialHeaderCipher);
  void setOneRttHeaderCipher(
      std::unique_ptr<PacketNumberCipher> oneRttHeaderCipher);
  void setZeroRttHeaderCipher(
      std::unique_ptr<PacketNumberCipher> zeroRttHeaderCipher);
  void setHandshakeHeaderCipher(
      std::unique_ptr<PacketNumberCipher> handshakeHeaderCipher);

  void setCodecParameters(CodecParameters params);
  void setClientConnectionId(ConnectionId connId);
  void setServerConnectionId(ConnectionId connId);
  void setStatelessResetToken(StatelessResetToken statelessResetToken);
  const ConnectionId& getClientConnectionId() const;
  const ConnectionId& getServerConnectionId() const;

  /**
   * Should be invoked when the state machine believes that the handshake is
   * complete.
   */
  void onHandshakeDone(TimePoint handshakeDoneTime);

  folly::Optional<TimePoint> getHandshakeDoneTime();

 private:
  CodecResult tryParseShortHeaderPacket(
      Buf data,
      const AckStates& ackStates,
      size_t dstConnIdSize,
      folly::io::Cursor& cursor);
  CodecResult parseLongHeaderPacket(
      BufQueue& queue,
      const AckStates& ackStates);

  [[nodiscard]] std::string connIdToHex() const;

  QuicNodeType nodeType_;

  CodecParameters params_;
  folly::Optional<ConnectionId> clientConnectionId_;
  folly::Optional<ConnectionId> serverConnectionId_;

  // Cipher used to decrypt handshake packets.
  std::unique_ptr<Aead> initialReadCipher_;

  std::unique_ptr<Aead> oneRttReadCipher_;
  std::unique_ptr<Aead> zeroRttReadCipher_;
  std::unique_ptr<Aead> handshakeReadCipher_;

  std::unique_ptr<PacketNumberCipher> initialHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> oneRttHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> zeroRttHeaderCipher_;
  std::unique_ptr<PacketNumberCipher> handshakeHeaderCipher_;

  folly::Optional<StatelessResetToken> statelessResetToken_;
  folly::Optional<TimePoint> handshakeDoneTime_;
};

} // namespace quic
