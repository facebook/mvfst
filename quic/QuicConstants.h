/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/chrono/Clock.h>
#include <folly/io/IOBuf.h>
#include <quic/common/third-party/enum.h>
#include <sys/types.h>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <ostream>
#include <string_view>
#include <vector>

/**
 * Namespace for mvfst chrono types.
 *
 * Using a separate namespace for clock types to minimize type conflicts in
 * tests and other code which may be using `using namespace quic` while also
 * having aliased chrono types.
 */
namespace quic::chrono {

using SteadyClock = folly::chrono::SteadyClock;
using SystemClock = folly::chrono::SystemClock;

} // namespace quic::chrono

namespace quic {

using Buf = std::unique_ptr<folly::IOBuf>;
using Clock = std::chrono::steady_clock;
using TimePoint = std::chrono::time_point<Clock>;
using DurationRep = std::chrono::microseconds::rep;
using namespace std::chrono_literals;

constexpr uint64_t kMaxVarInt = (1ull << 62) - 1;

// Default QUIC packet size for both read and write.
// TODO(xtt): make them configurable
constexpr uint64_t kDefaultV4UDPSendPacketLen = 1252;
constexpr uint64_t kDefaultV6UDPSendPacketLen = 1232;
// With Android NDK r15c for some apps we use gnu-libstdc++ instead of
// llvm-libc++. And gnu-libstdc++ doesn't like to make std::min constexpr.
constexpr uint16_t kDefaultUDPSendPacketLen =
    (kDefaultV4UDPSendPacketLen < kDefaultV6UDPSendPacketLen
         ? kDefaultV4UDPSendPacketLen
         : kDefaultV6UDPSendPacketLen);
// The max we will tolerate a peer's max_packet_size to be.
constexpr uint16_t kDefaultMaxUDPPayload = 1452;

// This is the minimum the max_packet_size transport parameter is allowed to be,
// per the spec. Note this actually refers to the max UDP payload size, not the
// maximum QUIC packet size.
constexpr uint16_t kMinMaxUDPPayload = 1200;

// How many bytes to reduce from udpSendPacketLen when socket write leads to
// EMSGSIZE.
constexpr uint16_t kDefaultMsgSizeBackOffSize = 50;

// Size of read buffer we provide to AsyncUDPSocket. The packet size cannot be
// larger than this, unless configured otherwise.
constexpr uint16_t kDefaultUDPReadBufferSize = 1500;

// Number of GRO buffers to use
// 1 means GRO is not enabled
// 64 is the max possible value
constexpr uint16_t kMinNumGROBuffers = 1;
constexpr uint16_t kMaxNumGROBuffers = 64;
constexpr uint16_t kDefaultNumGROBuffers = kMinNumGROBuffers;

constexpr uint16_t kMaxNumCoalescedPackets = 5;
// As per version 20 of the spec, transport parameters for private use must
// have ids with first byte being 0xff.
constexpr uint16_t kCustomTransportParameterThreshold = 0xff00;

// The length of the integrity tag present in a retry packet.
constexpr uint32_t kRetryIntegrityTagLen = 16;

// If the amount of data in the buffer of a QuicSocket equals or exceeds this
// threshold, then the callback registered through
// notifyPendingWriteOnConnection() will not be called
constexpr uint64_t kDefaultBufferSpaceAvailable =
    std::numeric_limits<uint64_t>::max();

// The default min rtt to use for a new connection
constexpr std::chrono::microseconds kDefaultMinRtt =
    std::chrono::microseconds::max();

// Default knob space for transport knobs (used for internal use-cases only)
constexpr uint64_t kDefaultQuicTransportKnobSpace = 0xfaceb001;

// Default knob id for transport knobs (used for internal use-cases only)
constexpr uint64_t kDefaultQuicTransportKnobId = 1;

BETTER_ENUM(
    PacketDropReason,
    uint8_t,
    NONE,
    CONNECTION_NOT_FOUND,
    DECRYPTION_ERROR,
    INVALID_PACKET_SIZE,
    INVALID_PACKET_SIZE_INITIAL,
    INVALID_PACKET_VERSION,
    INVALID_PACKET_INITIAL_BYTE,
    INVALID_PACKET_CID,
    INVALID_PACKET_VN,
    PARSE_ERROR_SHORT_HEADER,
    PARSE_ERROR_LONG_HEADER,
    PARSE_ERROR_LONG_HEADER_INITIAL,
    PARSE_ERROR_EXCEPTION,
    PARSE_ERROR_BAD_DCID,
    PARSE_ERROR_DCID,
    PARSE_ERROR_PACKET_BUFFERED,
    PARSE_ERROR_CLIENT,
    CIPHER_UNAVAILABLE,
    UNEXPECTED_RETRY,
    UNEXPECTED_RESET,
    UNEXPECTED_NOTHING,
    UNEXPECTED_PROTECTION_LEVEL,
    EMPTY_DATA,
    MAX_BUFFERED,
    BUFFER_UNAVAILABLE,
    PEER_ADDRESS_CHANGE,
    PROTOCOL_VIOLATION,
    ROUTING_ERROR_WRONG_HOST,
    SERVER_STATE_CLOSED,
    TRANSPORT_PARAMETER_ERROR,
    WORKER_NOT_INITIALIZED,
    SERVER_SHUTDOWN,
    INITIAL_CONNID_SMALL,
    CANNOT_MAKE_TRANSPORT,
    UDP_TRUNCATED,
    CLIENT_STATE_CLOSED,
    CLIENT_SHUTDOWN,
    INVALID_SRC_PORT,
    UNKNOWN_CID_VERSION,
    CANNOT_FORWARD_DATA)

BETTER_ENUM(
    TransportKnobParamId,
    uint64_t,
    // Any value not in the list below
    UNKNOWN = 0x0,
    // No-op
    NO_OP = 0x1,
    // Force udp payload size to be equal to max
    // udp payload size
    FORCIBLY_SET_UDP_PAYLOAD_SIZE = 0xba92,
    // Set congestion control algorithm
    CC_ALGORITHM_KNOB = 0xccaa,
    // Enable experimental CC settings
    CC_EXPERIMENTAL = 0xccac,
    // Change congestion control config struct
    CC_CONFIG = 0xccad,
    // Set pacing rtt factor used only during startup phase
    STARTUP_RTT_FACTOR_KNOB = 0x1111,
    // Set pacing rtt factor used when not in startup
    DEFAULT_RTT_FACTOR_KNOB = 0x2222,
    // Set max pacing rate in bytes per second to be used if pacing is enabled
    MAX_PACING_RATE_KNOB = 0x4444,
    // Use adaptive loss detection thresholds for reordering and timeout
    ADAPTIVE_LOSS_DETECTION = 0x5556,
    // Enable experimental pacer settings
    PACER_EXPERIMENTAL = 0x5557,
    // Set short header padding modulo size
    SHORT_HEADER_PADDING_KNOB = 0x6666,
    // Keepalive timer enabled
    KEEPALIVE_ENABLED = 0x7777,
    // Remove from loss buffer on spurious loss
    REMOVE_FROM_LOSS_BUFFER = 0x8888,
    // Knob for setting max pacing rate, with sequence number
    MAX_PACING_RATE_KNOB_SEQUENCED = 0x9999,
    // Control ACK_FREQUENCY policy
    ACK_FREQUENCY_POLICY = 0x10000,
    // Controls whether to fire write loops early when pacing
    FIRE_LOOP_EARLY = 0x10001,
    // Controls the timer tick used for pacing
    PACING_TIMER_TICK = 0x10002,
    // Controls default stream priority
    DEFAULT_STREAM_PRIORITY = 0x10003,
    // Controls write loop time fraction in terms of srtt
    WRITE_LOOP_TIME_FRACTION = 0x10004,
    // Controls number of times a stream gets a write in incremental mode
    WRITES_PER_STREAM = 0x10005,
    // Control connection migration
    CONNECTION_MIGRATION = 0x10006)

enum class FrameType : uint64_t {
  PADDING = 0x00,
  PING = 0x01,
  ACK = 0x02,
  ACK_ECN = 0x03,
  RST_STREAM = 0x04,
  STOP_SENDING = 0x05,
  CRYPTO_FRAME = 0x06, // librtmp has a #define CRYPTO
  NEW_TOKEN = 0x07,
  // STREAM frame can have values from 0x08 to 0x0f which indicate which fields
  // are present in the frame.
  STREAM = 0x08,
  STREAM_FIN = 0x09,
  STREAM_LEN = 0x0a,
  STREAM_LEN_FIN = 0x0b,
  STREAM_OFF = 0x0c,
  STREAM_OFF_FIN = 0x0d,
  STREAM_OFF_LEN = 0x0e,
  STREAM_OFF_LEN_FIN = 0x0f,
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
  // CONNECTION_CLOSE_APP_ERR frametype is use to indicate application errors
  CONNECTION_CLOSE_APP_ERR = 0x1D,
  HANDSHAKE_DONE = 0x1E,
  DATAGRAM = 0x30,
  DATAGRAM_LEN = 0x31,
  KNOB = 0x1550,
  IMMEDIATE_ACK = 0xAC,
  ACK_FREQUENCY = 0xAF,
  // Stream groups.
  GROUP_STREAM = 0x32,
  GROUP_STREAM_FIN = 0x33,
  GROUP_STREAM_LEN = 0x34,
  GROUP_STREAM_LEN_FIN = 0x35,
  GROUP_STREAM_OFF = 0x36,
  GROUP_STREAM_OFF_FIN = 0x37,
  GROUP_STREAM_OFF_LEN = 0x38,
  GROUP_STREAM_OFF_LEN_FIN = 0x39,
  ACK_RECEIVE_TIMESTAMPS = 0xB0
};

inline constexpr uint16_t toFrameError(FrameType frame) {
  return 0x0100 | static_cast<uint8_t>(frame);
}

enum class TransportErrorCode : uint64_t {
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
  INVALID_TOKEN = 0xb,
};

/**
 * Application error codes are opaque to QUIC transport.  Each application
 * protocol can define its own error codes.
 */
using ApplicationErrorCode = uint64_t;

/**
 * Example application error codes, or codes that can be used by very simple
 * applications.  Note: by convention error code 0 means no error.
 *
 * It is convenient to use not strongly typed enums so they are implicitly
 * castable to ints, but to get the scoping semantics we enclose it in a
 * namespace of the same name.
 */
namespace GenericApplicationErrorCode {
enum GenericApplicationErrorCode : uint64_t {
  NO_ERROR = 0,
  UNKNOWN = kMaxVarInt,
};
}

enum class LocalErrorCode : uint64_t {
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
  CONGESTION_CONTROL_ERROR = 0x4000000A,
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
  KNOB_FRAME_UNSUPPORTED = 0x4000001B,
  PACER_NOT_AVAILABLE = 0x4000001C,
  RTX_POLICIES_LIMIT_EXCEEDED = 0x4000001D,
};

enum class QuicNodeType : bool {
  Client,
  Server,
};

enum class QuicVersion : uint32_t {
  VERSION_NEGOTIATION = 0x00000000,
  // Before updating the MVFST version, please check
  // QuicTransportBase::isKnobSupported() and make sure that knob support is not
  // broken.
  MVFST = 0xfaceb002,
  QUIC_DRAFT = 0xff00001d, // Draft-29
  QUIC_V1 = 0x00000001,
  QUIC_V1_ALIAS = 0xfaceb003,
  // MVFST_EXPERIMENTAL used to set initial congestion window
  MVFST_EXPERIMENTAL = 0xfaceb00e, // Experimental alias for MVFST
  MVFST_ALIAS = 0xfaceb010,
  MVFST_INVALID = 0xfaceb00f,
  MVFST_EXPERIMENTAL2 = 0xfaceb011, // Experimental alias for MVFST
  MVFST_EXPERIMENTAL3 = 0xfaceb013, // Experimental alias for MVFST
};

using QuicVersionType = std::underlying_type<QuicVersion>::type;

constexpr uint32_t kDrainFactor = 3;

// batching mode
enum class QuicBatchingMode : uint32_t {
  BATCHING_MODE_NONE = 0,
  BATCHING_MODE_GSO = 1,
  BATCHING_MODE_SENDMMSG = 2,
  BATCHING_MODE_SENDMMSG_GSO = 3,
};

QuicBatchingMode getQuicBatchingMode(uint32_t val);

// default QUIC batching size - currently used only
// by BATCHING_MODE_GSO
constexpr uint32_t kDefaultQuicMaxBatchSize = 16;

// thread local delay
constexpr std::chrono::microseconds kDefaultThreadLocalDelay = 1ms;

// rfc6298:
constexpr int kRttAlpha = 8;
constexpr int kRttBeta = 4;

// Draft-17 recommends 100ms as initial RTT. We deliberately ignore that
// recommendation. This is not a bug.
constexpr std::chrono::microseconds kDefaultInitialRtt = 50000us;

// Timer tick interval
constexpr std::chrono::microseconds kGranularity = 10000us;

constexpr uint32_t kReorderingThreshold = 3;

// Current draft has 9 / 8. But our friends at Google told us they saw
// improvement with 5 / 4. Our tests also showed reduced retransmission with
// 5 / 4 without significantly huriting application latency.
constexpr DurationRep kDefaultTimeReorderingThreshDividend = 5;
constexpr DurationRep kDefaultTimeReorderingThreshDivisor = 4;

constexpr auto kPacketToSendForPTO = 2;

// Maximum number of packets to write per writeConnectionDataToSocket call.
constexpr uint64_t kDefaultWriteConnectionDataPacketLimit = 5;
// Minimum number of packets to write per burst in pacing
constexpr uint64_t kDefaultMinBurstPackets = 5;

// Default tick interval for pacing timer. This is the smallest interval the
// pacer will use as its interval.
constexpr std::chrono::microseconds kDefaultPacingTickInterval{1000};
// Default pacing timer resolution. This is the size of the buckets in the timer
// triggering the pacing callbacks. For pacing to work accurately, this should
// be reasonably smaller than kDefaultPacingTickInterval.
constexpr std::chrono::microseconds kDefaultPacingTimerResolution{100};
// Fraction of RTT that is used to limit how long a write function can loop
constexpr DurationRep kDefaultWriteLimitRttFraction = 25;

// Congestion control:
constexpr std::string_view kCongestionControlCubicStr = "cubic";
constexpr std::string_view kCongestionControlBbrStr = "bbr";
constexpr std::string_view kCongestionControlBbr2Str = "bbr2";
constexpr std::string_view kCongestionControlBbrTestingStr = "bbr_testing";
constexpr std::string_view kCongestionControlCopaStr = "copa";
constexpr std::string_view kCongestionControlCopa2Str = "copa2";
constexpr std::string_view kCongestionControlNewRenoStr = "newreno";
constexpr std::string_view kCongestionControlStaticCwndStr = "staticcwnd";
constexpr std::string_view kCongestionControlNoneStr = "none";

constexpr DurationRep kPersistentCongestionThreshold = 3;
enum class CongestionControlType : uint8_t {
  Cubic,
  NewReno,
  Copa,
  Copa2,
  BBR,
  BBR2,
  BBRTesting,
  StaticCwnd,
  None,
  // NOTE: MAX should always be at the end
  MAX
};
std::string_view congestionControlTypeToString(CongestionControlType type);
std::optional<CongestionControlType> congestionControlStrToType(
    std::string_view str);

// This is an approximation of a small enough number for cwnd to be blocked.
constexpr size_t kBlockedSizeBytes = 20;

constexpr uint64_t kInitCwndInMss = 10;
constexpr uint64_t kMinCwndInMss = 2;
// Min cwnd for BBR is 4 MSS regard less of transport settings
constexpr uint64_t kMinCwndInMssForBbr{4};

// Default max cwnd limit
constexpr uint64_t kDefaultMaxCwndInMss = 2000;
// Max cwnd limit for perf test purpose
constexpr uint64_t kLargeMaxCwndInMss = 860000;

// When server receives initial data without valid source address token,
// server will limit bytes in flight to avoid amplification attack until CFIN
// is received which proves sender owns the address.
constexpr uint64_t kLimitedCwndInMss = 5;

/* Hybrid slow start: */
// The first kAckSampling Acks within a RTT round will be used to sample delays
constexpr uint8_t kAckSampling = 8;
// Hystart won't exit slow start if Cwnd < kLowSsthresh
constexpr uint64_t kLowSsthreshInMss = 16;
// ACKs within kAckCountingGap are considered closely spaced, i.e., AckTrain
constexpr std::chrono::microseconds kAckCountingGap(2);
// Hystart's upper bound for DelayIncrease
constexpr std::chrono::microseconds kDelayIncreaseUpperBound(16ms);
// Hystart's lower bound for DelayIncrease
constexpr std::chrono::microseconds kDelayIncreaseLowerBound(4ms);

/* Cubic */
// Time elapsed scaling factor
constexpr double kTimeScalingFactor = 0.4;
// Default emulated connection numbers for each real connection
constexpr uint8_t kDefaultEmulatedConnection = 2;
// Default cwnd reduction factor:
constexpr float kDefaultCubicReductionFactor = 0.7f;
// Default W_max reduction factor when loss happens before Cwnd gets back to
// previous W_max:
constexpr float kDefaultLastMaxReductionFactor = 0.85f;
// Factor to control TCP estimate cwnd increase after Ack.
constexpr float kCubicTCPFriendlyEstimateIncreaseFactor =
    3 * (1 - kDefaultCubicReductionFactor) / (1 + kDefaultCubicReductionFactor);

/* Flow Control */
// Default flow control window for HTTP/2 + 1K for headers
constexpr uint64_t kDefaultStreamFlowControlWindow = (64 + 1) * 1024;
constexpr uint64_t kDefaultConnectionFlowControlWindow = 1024 * 1024;

/* Stream Limits */
constexpr uint64_t kDefaultMaxStreamsBidirectional = 2048;
constexpr uint64_t kDefaultMaxStreamsUnidirectional = 2048;
constexpr uint64_t kMaxStreamId = kMaxVarInt;
constexpr uint64_t kInvalidStreamId = kMaxStreamId + 1;
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
constexpr uint8_t kNonRtxRxPacketsPendingBeforeAck = 20;
// Default threshold before switching to the after init Ack frequency.
constexpr uint64_t kDefaultRxPacketsBeforeAckInitThreshold = 100;
// Default before init Ack frequency.
constexpr uint16_t kDefaultRxPacketsBeforeAckBeforeInit = 10;
// Default after init Ack frequency.
constexpr uint16_t kDefaultRxPacketsBeforeAckAfterInit = 10;

/* Ack timer */
// Ack timeout = SRTT * kAckTimerFactor
constexpr double kAckTimerFactor = 0.25;
// max ack timeout: 25ms
constexpr std::chrono::microseconds kMaxAckTimeout = 25000us;
// max_ack_delay cannot be equal or greater that 2^14
constexpr uint64_t kMaxAckDelay = 1ULL << 14;

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

// min connId size for one chosen by 'mvfst' as a peer (for version 1 of CID)
// the server id/worker id/process id info are in the first 4 bytes
constexpr size_t kMinSelfConnectionIdV1Size = 4;

// min connId size for one chosen by 'mvfst' as a peer (for version 2 of CID)
// the server id/worker id/process id info are in the first 6 bytes
constexpr size_t kMinSelfConnectionIdV2Size = 6;

// min connId size for one chosen by 'mvfst' as a peer (for version 3 of CID)
// the server id/worker id/process id info are in the first 7 bytes
constexpr size_t kMinSelfConnectionIdV3Size = 7;

// 22 bytes longer than minimum connection id.
constexpr uint16_t kMinStatelessPacketSize = 22 + kMinSelfConnectionIdV1Size;

constexpr std::chrono::milliseconds kHappyEyeballsV4Delay = 100ms;

constexpr std::chrono::milliseconds kHappyEyeballsConnAttemptDelayWithCache =
    15s;

constexpr size_t kMaxNumTokenSourceAddresses = 3;

// Amount of time to retain zero rtt keys until they are dropped after handshake
// completion.
constexpr std::chrono::seconds kTimeToRetainZeroRttKeys = 20s;

constexpr std::chrono::seconds kTimeToRetainLastCongestionAndRttState = 60s;

constexpr uint16_t kMaxNumMigrationsAllowed = 6;

constexpr auto kMinimumNumOfParamsInTheTicket = 8;

constexpr auto kStatelessResetTokenSecretLength = 32;

constexpr auto kRetryTokenSecretLength = 32;

// Number of milliseconds the retry token is valid for
// Set it to 5 minutes
constexpr uint64_t kMaxRetryTokenValidMs = 1000 * 60 * 5;

// Number of milliseconds the new token is valid for
// Set to 24h
constexpr uint64_t kMaxNewTokenValidMs = 1000 * 24 * 60 * 60;

// Default limit on active connection ids that a peer generates.
constexpr uint64_t kDefaultActiveConnectionIdLimit = 5;

// Maximum number of active connection ids to generate for the peer.
constexpr uint64_t kMaxActiveConnectionIdLimit = 5;

constexpr uint64_t kMaxPacketNumber = (1ull << 62) - 1;

// Use up to 3 bytes for the initial packet number.
constexpr uint32_t kMaxInitialPacketNum = 0xffffff;

// The maximum size of a DATAGRAM frame (including the frame type,
// length, and payload) the endpoint is willing to receive, in bytes.
// Disabled by default
constexpr uint16_t kDefaultMaxDatagramFrameSize = 0;
constexpr uint16_t kMaxDatagramFrameSize = 65535;
// Maximum overhead for a QUIC packet containing a single datagram frame
// i.e. Max Short Header + Max Datagram Frame Header
constexpr uint16_t kMaxDatagramPacketOverhead = 25 + 16;
// The Maximum number of datagrams (in/out) to buffer
constexpr uint32_t kDefaultMaxDatagramsBuffered = 75;

enum class ZeroRttSourceTokenMatchingPolicy : uint8_t {
  REJECT_IF_NO_EXACT_MATCH = 0,
  LIMIT_IF_NO_EXACT_MATCH = 1,
  ALWAYS_REJECT = 2,
};

inline std::string_view nodeToString(QuicNodeType node) {
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

enum class WriteDataReason {
  NO_WRITE,
  PROBES,
  ACK,
  CRYPTO_STREAM,
  STREAM,
  BLOCKED,
  STREAM_WINDOW_UPDATE,
  CONN_WINDOW_UPDATE,
  SIMPLE,
  RESET,
  PATHCHALLENGE,
  PING,
  DATAGRAM,
};

enum class NoWriteReason {
  WRITE_OK,
  EMPTY_SCHEDULER,
  NO_FRAME,
  NO_BODY,
  SOCKET_FAILURE,
};

enum class NoReadReason {
  READ_OK,
  TRUNCATED,
  EMPTY_DATA,
  RETRIABLE_ERROR,
  NONRETRIABLE_ERROR,
  STALE_DATA,
};

std::string_view writeDataReasonString(WriteDataReason reason);
std::string_view writeNoWriteReasonString(NoWriteReason reason);
std::string_view readNoReadReasonString(NoReadReason reason);

/**
 * Filter the versions that are currently supported.
 */
std::vector<QuicVersion> filterSupportedVersions(
    const std::vector<QuicVersion>&);

/**
 * Represent the different encryption levels used by QUIC.
 */
enum class EncryptionLevel : uint8_t {
  Initial,
  Handshake,
  EarlyData,
  AppData,
  MAX,
};

/**
 * This is a temporary type used during our data path experiment. It  may not
 * exist for long time.
 */
enum class DataPathType : uint8_t {
  ChainedMemory = 0,
  ContinuousMemory = 1,
};

// Stream priority level, can only be in [0, 7]
using PriorityLevel = uint8_t;
constexpr uint8_t kDefaultMaxPriority = 7;

constexpr size_t kShortHeaderPaddingModulo = 32;

// Maximum packet receive timestamps stored.
constexpr uint8_t kMaxReceivedPktsTimestampsStored = 10;
constexpr uint8_t kDefaultReceiveTimestampsExponent = 3;

} // namespace quic
