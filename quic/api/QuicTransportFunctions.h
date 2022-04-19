/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Expected.h>
#include <folly/io/async/AsyncUDPSocket.h>

#include <quic/QuicException.h>
#include <quic/api/IoBufQuicBatch.h>
#include <quic/api/QuicPacketScheduler.h>
#include <quic/api/QuicSocket.h>
#include <quic/state/StateData.h>

// Function to schedule writing data to socket. Return number of packets
// successfully scheduled
namespace quic {

struct DataPathResult {
  bool buildSuccess{false};
  bool writeSuccess{false};
  folly::Optional<SchedulingResult> result;
  uint64_t encodedSize{0};
  uint64_t encodedBodySize{0};

  static DataPathResult makeBuildFailure() {
    return DataPathResult();
  }

  static DataPathResult makeWriteResult(
      bool writeSuc,
      SchedulingResult&& res,
      uint64_t encodedSizeIn,
      uint64_t encodedBodySizeIn) {
    return DataPathResult(
        writeSuc, std::move(res), encodedSizeIn, encodedBodySizeIn);
  }

 private:
  explicit DataPathResult() = default;

  explicit DataPathResult(
      bool writeSuc,
      SchedulingResult&& res,
      uint64_t encodedSizeIn,
      uint64_t encodedBodySizeIn)
      : buildSuccess(true),
        writeSuccess(writeSuc),
        result(std::move(res)),
        encodedSize(encodedSizeIn),
        encodedBodySize(encodedBodySizeIn) {}
};

using DataPathFunc = std::function<DataPathResult(
    QuicConnectionStateBase&,
    PacketHeader,
    PacketNumberSpace,
    PacketNum,
    uint64_t,
    QuicPacketScheduler&,
    uint64_t,
    IOBufQuicBatch&,
    const Aead&,
    const PacketNumberCipher&)>;

using HeaderBuilder = std::function<PacketHeader(
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    PacketNum packetNum,
    QuicVersion version,
    const std::string& token)>;

using WritableBytesFunc =
    std::function<uint64_t(QuicConnectionStateBase& conn)>;

// Encapsulating the return value for the write functions.
// Useful because probes can go over the packet limit.
struct WriteQuicDataResult {
  uint64_t packetsWritten{};
  uint64_t probesWritten{};
  uint64_t bytesWritten{};
};

/**
 * Attempts to write data from all frames in the QUIC connection into the UDP
 * socket supplied with the aead and the headerCipher.
 */
WriteQuicDataResult writeQuicDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    TimePoint writeLoopBeginTime = Clock::now());

/**
 * Writes only the crypto and ack frames to the socket.
 *
 * return the number of packets written to socket.
 */
WriteQuicDataResult writeCryptoAndAckDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types packetType,
    Aead& cleartextCipher,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit,
    const std::string& token = std::string());

/**
 * Writes out all the data streams without writing out crypto streams.
 * This is useful when the crypto stream still needs to be sent in separate
 * packets and cannot use the encryption of the data key.
 */
WriteQuicDataResult writeQuicDataExceptCryptoStreamToSocket(
    folly::AsyncUDPSocket& socket,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit);

/**
 * Writes frame data including zero rtt data to the socket with the supplied
 * zero rtt cipher.
 */
uint64_t writeZeroRttDataToSocket(
    folly::AsyncUDPSocket& socket,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    uint64_t packetLimit);

/**
 * Whether we should and can write data.
 *
 */
WriteDataReason shouldWriteData(QuicConnectionStateBase& conn);
bool hasAckDataToWrite(const QuicConnectionStateBase& conn);
WriteDataReason hasNonAckDataToWrite(const QuicConnectionStateBase& conn);

/**
 * Invoked when the written stream data was new stream data.
 */
void handleNewStreamDataWritten(
    QuicStreamLike& stream,
    uint64_t frameLen,
    bool frameFin);

/**
 * Invoked when the stream data written was retransmitted data.
 */
void handleRetransmissionWritten(
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    std::deque<StreamBuffer>::iterator lossBufferIter);

/**
 * Update the connection and stream state after stream data is written and deal
 * with new data, as well as retranmissions. Returns true if the data sent is
 * new data.
 */
bool handleStreamWritten(
    QuicConnectionStateBase& conn,
    QuicStreamLike& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace);

bool handleStreamBufMetaWritten(
    QuicConnectionStateBase& conn,
    QuicStreamState& stream,
    uint64_t frameOffset,
    uint64_t frameLen,
    bool frameFin,
    PacketNum packetNum,
    PacketNumberSpace packetNumberSpace);

/**
 * Update the connection state after sending a new packet.
 */
void updateConnection(
    QuicConnectionStateBase& conn,
    folly::Optional<PacketEvent> packetEvent,
    RegularQuicWritePacket packet,
    TimePoint time,
    uint32_t encodedSize,
    uint32_t encodedBodySize,
    bool isDSRPacket);

/**
 * Returns the number of writable bytes available for constructing a PTO packet.
 * This will either return std::numeric_limits<uint64_t>::max() or the number
 * of bytes until the writableBytesLimit is reached – depending on whether the
 * client's address has been validated.
 */
uint64_t probePacketWritableBytes(QuicConnectionStateBase& conn);

/**
 * Returns the minimum available bytes window out of path validation rate
 * limiting, 0-rtt total bytes sent limiting, and the congestion controller.
 */
uint64_t congestionControlWritableBytes(QuicConnectionStateBase& conn);

uint64_t unlimitedWritableBytes(QuicConnectionStateBase&);

void writeCloseCommon(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    PacketHeader&& header,
    folly::Optional<QuicError> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher);

/**
 * Writes a LongHeader packet with a close frame.
 * The close frame type written depends on the type of error in closeDetails.
 */
void writeLongClose(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    LongHeader::Types headerType,
    folly::Optional<QuicError> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion);

/**
 * Write a short header packet with a close frame.
 * The close frame type written depends on the type of error in closeDetails.
 */
void writeShortClose(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& connId,
    folly::Optional<QuicError> closeDetails,
    const Aead& aead,
    const PacketNumberCipher& headerCipher);

/**
 * Encrypts the packet header for the header type.
 * This will overwrite the header with the encrypted header form. It will verify
 * whether or not there are enough bytes to sample for the header encryption
 * from the encryptedBody via a CHECK.
 */
void encryptPacketHeader(
    HeaderForm headerForm,
    uint8_t* header,
    size_t headerLen,
    const uint8_t* encryptedBody,
    size_t bodyLen,
    const PacketNumberCipher& headerCipher);

/**
 * Writes the connections data to the socket using the header
 * builder as well as the scheduler. This will write the amount of
 * data allowed by the writableBytesFunc and will only write a maximum
 * number of packetLimit packets at each invocation.
 */
WriteQuicDataResult writeConnectionDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    HeaderBuilder builder,
    PacketNumberSpace pnSpace,
    QuicPacketScheduler& scheduler,
    const WritableBytesFunc& writableBytesFunc,
    uint64_t packetLimit,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    TimePoint writeLoopBeginTime,
    const std::string& token = std::string());

uint64_t writeProbingDataToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const HeaderBuilder& builder,
    EncryptionLevel encryptionLevel,
    PacketNumberSpace pnSpace,
    FrameScheduler scheduler,
    uint8_t probesToSend,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version,
    const std::string& token = std::string());

uint64_t writeD6DProbeToSocket(
    folly::AsyncUDPSocket& sock,
    QuicConnectionStateBase& connection,
    const ConnectionId& srcConnId,
    const ConnectionId& dstConnId,
    const Aead& aead,
    const PacketNumberCipher& headerCipher,
    QuicVersion version);

HeaderBuilder LongHeaderBuilder(LongHeader::Types packetType);
HeaderBuilder ShortHeaderBuilder();

void maybeSendStreamLimitUpdates(QuicConnectionStateBase& conn);

void implicitAckCryptoStream(
    QuicConnectionStateBase& conn,
    EncryptionLevel encryptionLevel);
void handshakeConfirmed(QuicConnectionStateBase& conn);
bool hasInitialOrHandshakeCiphers(QuicConnectionStateBase& conn);

bool writeLoopTimeLimit(
    TimePoint loopBeginTime,
    const QuicConnectionStateBase& connection);

} // namespace quic
