/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Optional.h>
#include <quic/codec/Decode.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/codec/Types.h>
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
  PacketNum packetNum;
  ProtectionType protectionType;

  CipherUnavailable(
      Buf packetIn,
      PacketNum packetNumIn,
      ProtectionType protectionTypeIn)
      : packet(std::move(packetIn)),
        packetNum(packetNumIn),
        protectionType(protectionTypeIn) {}
};

using CodecResult = boost::variant<
    RegularQuicPacket,
    folly::Optional<CipherUnavailable>,
    StatelessReset>;

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
      folly::IOBufQueue& queue,
      const AckStates& ackStates);

  /**
   * Tries to parse the packet and returns whether or not
   * it is a version negotiation packet.
   * This returns folly::none if the packet is either not
   * a VN packet or is invalid.
   */
  folly::Optional<VersionNegotiationPacket> tryParsingVersionNegotiation(
      folly::IOBufQueue& queue);

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

  /**
   * Should be invoked when the state machine believes that the handshake is
   * complete.
   */
  void onHandshakeDone(TimePoint handshakeDoneTime);

  folly::Optional<TimePoint> getHandshakeDoneTime();

 private:
  CodecResult parseLongHeaderPacket(
      folly::IOBufQueue& queue,
      const AckStates& ackStates);

  std::string connIdToHex();

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
