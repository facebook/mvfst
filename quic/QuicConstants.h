/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <boost/variant.hpp>
#include <folly/Range.h>
#include <folly/String.h>
#include <chrono>
#include <cstdint>

namespace quic {

using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;
using namespace std::chrono_literals;

// Default QUIC packet size for both read and write.
constexpr uint64_t kDefaultV4UDPSendPacketLen = 1252;
constexpr uint64_t kDefaultV6UDPSendPacketLen = 1232;
// With Android NDK r15c for some apps we use gnu-libstdc++ instead of
// llvm-libc++. And gnu-libstdc++ doesn't like to make std::min constexpr.
constexpr uint16_t kDefaultUDPSendPacketLen =
    (kDefaultV4UDPSendPacketLen < kDefaultV6UDPSendPacketLen
         ? kDefaultV4UDPSendPacketLen
         : kDefaultV6UDPSendPacketLen);
// This is the default if the transport parameter for max packet size is missing
// or zero.
constexpr uint16_t kDefaultMaxUDPPayload = 65527;

// This is the minimum the max_packet_size transport parameter is allowed to be,
// per the spec. Note this actually refers to the max UDP payload size, not the
// maximum QUIC packet size.
constexpr uint16_t kMinMaxUDPPayload = 1200;

// How many bytes to reduce from udpSendPacketLen when socket write leads to
// EMSGSIZE.
constexpr uint16_t kDefaultMsgSizeBackOffSize = 50;

// Size of read buffer we provide to AsyncUDPSocket. The packet size cannot be
// larger than this, unless configured otherwise.
constexpr uint16_t kDefaultUDPReadBufferSize = 4096;

constexpr uint16_t kMaxNumCoalescedPackets = 5;
// As per version 20 of the spec, transport parameters for private use must
// have ids with first byte being 0xff.
constexpr uint16_t kCustomTransportParameterThreshold = 0xff00;

// If the amount of data in the buffer of a QuicSocket equals or exceeds this
// threshold, then the callback registered through
// notifyPendingWriteOnConnection() will not be called
constexpr uint64_t kDefaultBufferSpaceAvailable =
    std::numeric_limits<uint64_t>::max();

// Frames types with values defines in Quic Draft 15+
enum class FrameType : uint8_t {
  PADDING = 0x00,
  PING = 0x01,
  ACK = 0x02,
  ACK_ECN = 0x03,
  RST_STREAM = 0x04,
  STOP_SENDING = 0x05,
  CRYPTO_FRAME = 0x06, // librtmp has a #define CRYPTO
  NEW_TOKEN = 0x07,
  // STREAM frame can have values from 0x08 to 0x0f
  STREAM = 0x08,
  MAX_DATA = 0x10,
  MAX_STREAM_DATA = 0x11,
  MAX_STREAMS_BIDI = 0x12,
  MAX_STREAMS_UNI = 0x13,
  DATA_BLOCKED = 0x14,
  STREAM_DATA_BLOCKED = 0x15,
  STREAMS_BLOCKED_BIDI = 0x16,
  STREAMS_BLOCKED_UNI = 0x17,
  NEW_CONNECTION_ID = 0x18,
  RETIRE_CONNECTION_ID = 0x19,
  PATH_CHALLENGE = 0x1A,
  PATH_RESPONSE = 0x1B,
  CONNECTION_CLOSE = 0x1C,
  APPLICATION_CLOSE = 0x1D,
  MIN_STREAM_DATA = 0xFE, // subject to change (https://fburl.com/qpr)
  EXPIRED_STREAM_DATA = 0xFF, // subject to change (https://fburl.com/qpr)
};

inline constexpr uint16_t toFrameError(FrameType frame) {
  return 0x0100 | static_cast<uint8_t>(frame);
}

enum class TransportErrorCode : uint16_t {
  NO_ERROR = 0x0000,
  INTERNAL_ERROR = 0x0001,
  SERVER_BUSY = 0x0002,
  FLOW_CONTROL_ERROR = 0x0003,
  STREAM_LIMIT_ERROR = 0x0004,
  STREAM_STATE_ERROR = 0x0005,
  FINAL_SIZE_ERROR = 0x0006,
  FRAME_ENCODING_ERROR = 0x0007,
  TRANSPORT_PARAMETER_ERROR = 0x0008,
  PROTOCOL_VIOLATION = 0x000A,
  INVALID_MIGRATION = 0x000C,
  CRYPTO_ERROR = 0x100,
  CRYPTO_ERROR_MAX = 0x1ff,
};

/**
 * Application error codes are opaque to QUIC transport.  Each application
 * protocol can define its own error codes.
 */
using ApplicationErrorCode = uint16_t;

/**
 * Example application error codes, or codes that can be used by very simple
 * applications.  Note: by convention error code 0 means no error.
 *
 * It is convenient to use not strongly typed enums so they are implicitly
 * castable to ints, but to get the scoping semantics we enclose it in a
 * namespace of the same name.
 */
namespace GenericApplicationErrorCode {
enum GenericApplicationErrorCode : uint16_t {
  NO_ERROR = 0x0000,
  UNKNOWN = 0xFFFF
};
}

enum class LocalErrorCode : uint32_t {
  // Local errors
  NO_ERROR = 0x00000000,
  CONNECT_FAILED = 0x40000000,
  CODEC_ERROR = 0x40000001,
  STREAM_CLOSED = 0x40000002,
  STREAM_NOT_EXISTS = 0x40000003,
  CREATING_EXISTING_STREAM = 0x40000004,
  SHUTTING_DOWN = 0x40000005,
  RESET_CRYPTO_STREAM = 0x40000006,
  CWND_OVERFLOW = 0x40000007,
  INFLIGHT_BYTES_OVERFLOW = 0x40000008,
  LOST_BYTES_OVERFLOW = 0x40000009,
  // This is a retryable error. When encountering this error,
  // the user should retry the request.
  NEW_VERSION_NEGOTIATED = 0x4000000A,
  INVALID_WRITE_CALLBACK = 0x4000000B,
  TLS_HANDSHAKE_FAILED = 0x4000000C,
  APP_ERROR = 0x4000000D,
  INTERNAL_ERROR = 0x4000000E,
  TRANSPORT_ERROR = 0x4000000F,
  INVALID_WRITE_DATA = 0x40000010,
  INVALID_STATE_TRANSITION = 0x40000011,
  CONNECTION_CLOSED = 0x40000012,
  EARLY_DATA_REJECTED = 0x40000013,
  CONNECTION_RESET = 0x40000014,
  IDLE_TIMEOUT = 0x40000015,
  PACKET_NUMBER_ENCODING = 0x40000016,
  INVALID_OPERATION = 0x40000017,
  STREAM_LIMIT_EXCEEDED = 0x40000018,
  CONNECTION_ABANDONED = 0x40000019,
  CALLBACK_ALREADY_INSTALLED = 0x4000001A,
};

using QuicErrorCode =
    boost::variant<ApplicationErrorCode, LocalErrorCode, TransportErrorCode>;

enum class QuicNodeType : bool {
  Client,
  Server,
};

enum class QuicVersion : uint32_t {
  VERSION_NEGOTIATION = 0x00000000,
  MVFST = 0xfaceb000,
  QUIC_DRAFT = 0xFF000011, // Draft-17
  MVFST_INVALID = 0xfaceb00f,
};

using QuicVersionType = std::underlying_type<QuicVersion>::type;

using TransportPartialReliabilitySetting = bool;

constexpr uint16_t kPartialReliabilityParameterId = 0xFF00; // subject to change

constexpr uint32_t kDrainFactor = 3;

// batching mode
enum class QuicBatchingMode : uint32_t {
  BATCHING_MODE_NONE = 0,
  BATCHING_MODE_GSO = 1,
  BATCHING_MODE_SENDMMSG = 2,
};

QuicBatchingMode getQuicBatchingMode(uint32_t val);

// default QUIC batching size - currently used only
// by BATCHING_MODE_GSO
constexpr uint32_t kDefaultQuicMaxBatchSize = 16;

// rfc6298:
constexpr int kRttAlpha = 8;
constexpr int kRttBeta = 4;

// Draft-17 recommends 100ms as initial RTT. We delibrately ignore that
// recommendation. This is not a bug.
constexpr std::chrono::microseconds kDefaultInitialRtt = 50000us;

// HHWheelTimer tick interval
constexpr std::chrono::microseconds kGranularity = 10000us;

constexpr uint32_t kReorderingThreshold = 3;

constexpr auto kPacketToSendForPTO = 2;

// Maximum number of packets to write per writeConnectionDataToSocket call.
constexpr uint64_t kDefaultWriteConnectionDataPacketLimit = 5;
// Maximum number of packets to write per burst in pacing
constexpr uint64_t kDefaultMaxBurstPackets = 10;
// Default timer tick interval for pacing timer
// the microsecond timers are accurate to  about 5 usec
// but the notifications can get delayed if the event loop is busy
// this is subject to testing but I would suggest a value >= 200usec
constexpr std::chrono::microseconds kDefaultPacingTimerTickInterval{1000};

// Congestion control:
constexpr std::chrono::microseconds::rep kPersistentCongestionThreshold = 3;
enum class CongestionControlType : uint8_t { Cubic, NewReno, Copa, BBR, None };
// This is an approximation of a small enough number for cwnd to be blocked.
constexpr size_t kBlockedSizeBytes = 20;

constexpr uint64_t kInitCwndInMss = 10;
constexpr uint64_t kMinCwndInMss = 2;
constexpr uint64_t kDefaultMaxCwndInMss = 2000;
// When server receives early data attempt without valid source address token,
// server will limit bytes in flight to avoid amplification attack until CFIN
// is received which proves sender owns the address.
constexpr uint64_t kLimitedCwndInMss = 3;

/* Hybrid slow start: */
// The first kAckSampling Acks within a RTT round will be used to sample delays
constexpr uint8_t kAckSampling = 8;
// Hystart won't exit slow start if Cwnd < kLowSsthresh
constexpr uint64_t kLowSsthreshInMss = 16;
// ACKs within kAckCountingGap are considered closely spaced, i.e., AckTrain
constexpr std::chrono::microseconds kAckCountingGap(2);
// Hystart's upper bound for DelayIncrease
constexpr std::chrono::microseconds kDelayIncreaseUpperBound(8);
// Hystart's lower bound for DelayIncrease
constexpr std::chrono::microseconds kDelayIncreaseLowerBound(2);

/* Cubic */
// Default cwnd reduction factor:
constexpr double kDefaultCubicReductionFactor = 0.8;
// Time elapsed scaling factor
constexpr double kTimeScalingFactor = 0.4;
// Default emulated connection numbers for each real connection
constexpr uint8_t kDefaultEmulatedConnection = 2;
// Default W_max reduction factor when loss happens before Cwnd gets back to
// previous W_max:
constexpr float kDefaultLastMaxReductionFactor = 0.85f;

/* Flow Control */
// Default flow control window for HTTP/2 + 1K for headers
constexpr uint64_t kDefaultStreamWindowSize = (64 + 1) * 1024;
constexpr uint64_t kDefaultConnectionWindowSize = 1024 * 1024;

/* Stream Limits */
constexpr uint64_t kDefaultMaxStreamsBidirectional = 2048;
constexpr uint64_t kDefaultMaxStreamsUnidirectional = 2048;
constexpr uint64_t kMaxStreamId = 1ull << 62;
constexpr uint64_t kMaxMaxStreams = 1ull << 60;

/* Idle timeout parameters */
// Default idle timeout to advertise.
constexpr auto kDefaultIdleTimeout = 60000ms;
constexpr auto kMaxIdleTimeout = 600000ms;

// Time format related:
constexpr uint8_t kQuicTimeExpoBits = 5;
constexpr uint8_t kQuicTimeMantissaBits = 16 - kQuicTimeExpoBits;
// This is the largest possible value with a exponent = 0:
constexpr uint16_t kLargestQuicTimeWithoutExpo = 0xFFF;
// Largest possible value with a positive exponent:
constexpr uint64_t kLargestQuicTime = 0x0FFFull << (0x1F - 1);

// Limit of non-retransmittable packets received before an Ack has to be
// emitted.
constexpr uint8_t kNonRxPacketsPendingBeforeAckThresh = 20;
// Limit of retransmittable packets received before an Ack has to be emitted.
constexpr uint8_t kRxPacketsPendingBeforeAckThresh = 10;

/* Ack timer */
// TODO: These numbers are shamlessly taken from Chromium code. We have no idea
// how good/bad this is.
// Ack timeout = SRTT * kAckTimerFactor
constexpr double kAckTimerFactor = 0.25;
// max ack timeout: 25ms
constexpr std::chrono::microseconds kMaxAckTimeout = 25000us;
// min ack timeout: 10ms
constexpr std::chrono::microseconds kMinAckTimeout = 10000us;

constexpr uint64_t kAckPurgingThresh = 10;

// Default number of packets to buffer if keys are not present.
constexpr uint32_t kDefaultMaxBufferedPackets = 20;

// Default exponent to use while computing ack delay.
constexpr uint64_t kDefaultAckDelayExponent = 3;
constexpr uint64_t kMaxAckDelayExponent = 20;

// Default connection id size of the connection id we will send.
constexpr size_t kDefaultConnectionIdSize = 8;

// Minimum size of the health check token. This is used to reduce the impact of
// amplification attacks.
constexpr size_t kMinHealthCheckTokenSize = 5;

// Maximum size of the reason phrase.
constexpr size_t kMaxReasonPhraseLength = 1024;

// Minimum size of an initial packet
constexpr size_t kMinInitialPacketSize = 1200;

// Default maximum PTOs that will happen before tearing down the connection
constexpr uint16_t kDefaultMaxNumPTO = 7;

// Maximum early data size that we need to negotiate in TLS
constexpr uint32_t kRequiredMaxEarlyDataSize = 0xffffffff;

// The minimum size of a stateless reset packet. This is the short header size,
// and 16 bytes of the token and 16 bytes of randomness
constexpr uint16_t kMinStatelessPacketSize = 13 + 16 + 16;

constexpr std::chrono::milliseconds kHappyEyeballsV4Delay = 150ms;

constexpr std::chrono::milliseconds kHappyEyeballsConnAttemptDelayWithCache =
    15s;

constexpr size_t kMaxNumTokenSourceAddresses = 3;

// Amount of time to retain initial keys until they are dropped after handshake
// completion.
constexpr std::chrono::seconds kTimeToRetainInitialKeys = 20s;

// Amount of time to retain zero rtt keys until they are dropped after handshake
// completion.
constexpr std::chrono::seconds kTimeToRetainZeroRttKeys = 20s;

constexpr std::chrono::seconds kTimeToRetainLastCongestionAndRttState = 60s;

constexpr uint32_t kMaxNumMigrationsAllowed = 6;

constexpr auto kExpectedNumOfParamsInTheTicket = 8;

constexpr auto kStatelessResetTokenSecretLength = 32;

// default capability of QUIC partial reliability
constexpr TransportPartialReliabilitySetting kDefaultPartialReliability = false;

enum class ZeroRttSourceTokenMatchingPolicy : uint8_t {
  REJECT_IF_NO_EXACT_MATCH,
  LIMIT_IF_NO_EXACT_MATCH,
  // T33014230 Subnet matching
  // REJECT_IF_NO_SUBNECT_MATCH,
  // LIMIT_IF_NO_EXACT_MATCH
};

inline folly::StringPiece nodeToString(QuicNodeType node) {
  if (node == QuicNodeType::Client) {
    return "Client";
  } else {
    return "Server";
  }
}

template <class T>
inline std::ostream& operator<<(std::ostream& os, const std::vector<T>& v) {
  for (auto it = v.cbegin(); it != v.cend(); ++it) {
    os << *it;
    if (std::next(it) != v.cend()) {
      os << ",";
    }
  }
  return os;
}

inline std::ostream& operator<<(std::ostream& os, const QuicVersion& v) {
  os << static_cast<std::underlying_type<QuicVersion>::type>(v);
  return os;
}

/**
 * Filter the versions that are currently supported.
 */
std::vector<QuicVersion> filterSupportedVersions(
    const std::vector<QuicVersion>&);
} // namespace quic
