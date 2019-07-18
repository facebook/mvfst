/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/String.h>

namespace quic {
constexpr folly::StringPiece kShortHeaderPacketType = "1RTT";
constexpr folly::StringPiece kVersionNegotiationPacketType =
    "VersionNegotiation";
constexpr folly::StringPiece kHTTP3ProtocolType = "QUIC_HTTP3";
constexpr folly::StringPiece kNoError = "no error";
constexpr folly::StringPiece kGracefulExit = "graceful exit";
constexpr folly::StringPiece kPersistentCongestion = "persistent congestion";
constexpr folly::StringPiece kRemoveInflight = "remove bytes in flight";
constexpr folly::StringPiece kCubicSkipLoss = "cubic skip loss";
constexpr folly::StringPiece kCubicLoss = "cubic loss";
constexpr folly::StringPiece kCubicSteadyCwnd = "cubic steady cwnd";
constexpr folly::StringPiece kCubicSkipAck = "cubic skip ack";
constexpr folly::StringPiece kCongestionPacketAck = "congestion packet ack";
constexpr folly::StringPiece kCwndNoChange = "cwnd no change";
constexpr folly::StringPiece kAckInQuiescence = "ack in quiescence";
constexpr folly::StringPiece kResetTimeToOrigin = "reset time to origin";
constexpr folly::StringPiece kResetLastReductionTime =
    "reset last reduction time";
constexpr folly::StringPiece kRenoCwndEstimation = "reno cwnd estimation";
constexpr folly::StringPiece kPacketAckedInRecovery =
    "packet acked in recovery";
constexpr folly::StringPiece kCopaInit = "copa init";
constexpr folly::StringPiece kCongestionPacketSent =
    "congestion on packet sent";
constexpr folly::StringPiece kCopaCheckAndUpdateDirection =
    "copa check and update direction";
constexpr folly::StringPiece kCongestionPacketLoss = "congestion packet loss";
constexpr folly::StringPiece kCongestionAppLimited = "congestion app limited";
constexpr folly::StringPiece kCongestionAppUnlimited =
    "congestion app unlimited";
constexpr uint64_t kDefaultCwnd = 12320;
constexpr folly::StringPiece kAppIdle = "app idle";
constexpr folly::StringPiece kMaxBuffered = "max buffered";
constexpr folly::StringPiece kCipherUnavailable = "cipher unavailable";
constexpr folly::StringPiece kParse = "parse";
constexpr folly::StringPiece kNonRegular = "non regular";
constexpr folly::StringPiece kAlreadyClosed = "already closed";
constexpr folly::StringPiece kUdpTruncated = "udp truncated";
constexpr folly::StringPiece kNoData = "no data";
constexpr folly::StringPiece kUnexpectedProtectionLevel =
    "unexpected protection level";
constexpr folly::StringPiece kBufferUnavailable = "buffer unavailable";
constexpr folly::StringPiece kReset = "reset";
constexpr folly::StringPiece kPtoAlarm = "pto alarm";
constexpr folly::StringPiece kHandshakeAlarm = "handshake alarm";

} // namespace quic
