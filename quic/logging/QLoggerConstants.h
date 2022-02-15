/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/String.h>
#include <quic/QuicConstants.h>
#include <quic/codec/Types.h>

namespace quic {
constexpr folly::StringPiece kShortHeaderPacketType = "1RTT";
constexpr auto kVersionNegotiationPacketType = "version_negotiation";
constexpr auto kHTTP3ProtocolType = "QUIC_HTTP3";
constexpr auto kNoError = "no error";
constexpr auto kGracefulExit = "graceful exit";
constexpr auto kPersistentCongestion = "persistent congestion";
constexpr auto kRemoveInflight = "remove bytes in flight";
constexpr auto kCubicSkipLoss = "cubic skip loss";
constexpr auto kCubicLoss = "cubic loss";
constexpr auto kCubicSteadyCwnd = "cubic steady cwnd";
constexpr auto kCubicSkipAck = "cubic skip ack";
constexpr auto kCubicInit = "cubic init";
constexpr auto kCongestionPacketAck = "congestion packet ack";
constexpr auto kCwndNoChange = "cwnd no change";
constexpr auto kAckInQuiescence = "ack in quiescence";
constexpr auto kResetTimeToOrigin = "reset time to origin";
constexpr auto kResetLastReductionTime = "reset last reduction time";
constexpr auto kRenoCwndEstimation = "reno cwnd estimation";
constexpr auto kPacketAckedInRecovery = "packet acked in recovery";
constexpr auto kCopaInit = "copa init";
constexpr auto kCongestionPacketSent = "congestion on packet sent";
constexpr auto kCopaCheckAndUpdateDirection = "copa check and update direction";
constexpr auto kCongestionPacketLoss = "congestion packet loss";
constexpr auto kAppLimited = "app limited";
constexpr auto kAppUnlimited = "app unlimited";
constexpr uint64_t kDefaultCwnd = 12320;
constexpr auto kAppIdle = "app idle";
constexpr auto kMaxBuffered = "max buffered";
constexpr auto kCipherUnavailable = "cipher unavailable";
constexpr auto kParse = "parse";
constexpr auto kNonRegular = "non regular";
constexpr auto kAlreadyClosed = "already closed";
constexpr auto kUdpTruncated = "udp truncated";
constexpr auto kNoData = "no data";
constexpr auto kUnexpectedProtectionLevel = "unexpected protection level";
constexpr auto kBufferUnavailable = "buffer unavailable";
constexpr auto kReset = "reset";
constexpr auto kRetry = "retry";
constexpr auto kPtoAlarm = "pto alarm";
constexpr auto kHandshakeAlarm = "handshake alarm";
constexpr auto kLossTimeoutExpired = "loss timeout expired";
constexpr auto kStart = "start";
constexpr auto kWriteNst = "write nst";
constexpr auto kTransportReady = "transport ready";
constexpr auto kDerivedZeroRttReadCipher = "derived 0-rtt read cipher";
constexpr auto kDerivedOneRttReadCipher = "derived 1-rtt read cipher";
constexpr auto kDerivedOneRttWriteCipher = "derived 1-rtt write cipher";
constexpr auto kZeroRttRejected = "zerortt rejected";
constexpr auto kZeroRttAccepted = "zerortt accepted";
constexpr auto kZeroRttAttempted = "zerortt attempted";
constexpr auto kRecalculateTimeToOrigin = "recalculate time to origin";
constexpr auto kAbort = "abort";
constexpr auto kQLogVersion = "draft-00";
constexpr auto kQLogTitle = "mvfst qlog";
constexpr auto kQLogDescription = "Converted from file";
constexpr auto kQLogTraceTitle = "mvfst qlog from single connection";
constexpr auto kQLogTraceDescription = "Generated qlog from connection";
constexpr auto kQLogTimeUnits = "us";
constexpr auto kQLogVersionField = "qlog_version";
constexpr auto kQLogTitleField = "title";
constexpr auto kQLogDescriptionField = "description";
constexpr auto kQLogTraceCountField = "trace_count";
constexpr auto kEOM = "eom";
constexpr auto kOnEOM = "on eom";
constexpr auto kStreamBlocked = "stream blocked";
constexpr auto kHeaders = "headers";
constexpr auto kOnHeaders = "on headers";
constexpr auto kOnError = "on error";
constexpr auto kPushPromise = "push promise";
constexpr auto kBody = "body";

constexpr folly::StringPiece kQLogServerVantagePoint = "server";
constexpr folly::StringPiece kQLogClientVantagePoint = "client";

using VantagePoint = QuicNodeType;

folly::StringPiece vantagePointString(VantagePoint vantagePoint) noexcept;

folly::StringPiece toQlogString(FrameType frame);

folly::StringPiece toQlogString(LongHeader::Types type);

} // namespace quic
