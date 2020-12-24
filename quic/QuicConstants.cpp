/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/QuicConstants.h>

namespace quic {

folly::StringPiece congestionControlTypeToString(CongestionControlType type) {
  switch (type) {
    case CongestionControlType::Cubic:
      return kCongestionControlCubicStr;
    case CongestionControlType::BBR:
      return kCongestionControlBbrStr;
    case CongestionControlType::Copa:
      return kCongestionControlCopaStr;
    case CongestionControlType::Copa2:
      return kCongestionControlCopa2Str;
    case CongestionControlType::NewReno:
      return kCongestionControlNewRenoStr;
    case CongestionControlType::None:
      return kCongestionControlNoneStr;
    case CongestionControlType::CCP:
      return kCongestionControlCcpStr;
    default:
      return "unknown";
  }
}

folly::Optional<CongestionControlType> congestionControlStrToType(
    folly::StringPiece str) {
  if (str == kCongestionControlCubicStr) {
    return quic::CongestionControlType::Cubic;
  } else if (str == kCongestionControlBbrStr) {
    return quic::CongestionControlType::BBR;
  } else if (str == kCongestionControlCopaStr) {
    return quic::CongestionControlType::Copa;
  } else if (str == kCongestionControlCopa2Str) {
    return quic::CongestionControlType::Copa2;
  } else if (str == kCongestionControlNewRenoStr) {
    return quic::CongestionControlType::NewReno;
  } else if (str == kCongestionControlNoneStr) {
    return quic::CongestionControlType::None;
  } else if (str == kCongestionControlCcpStr) {
    return quic::CongestionControlType::CCP;
  }
  return folly::none;
}

QuicBatchingMode getQuicBatchingMode(uint32_t val) {
  switch (val) {
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_NONE):
      return QuicBatchingMode::BATCHING_MODE_NONE;
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_GSO):
      return QuicBatchingMode::BATCHING_MODE_GSO;
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_SENDMMSG):
      return QuicBatchingMode::BATCHING_MODE_SENDMMSG;
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO):
      return QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO;
      // no default
  }

  return QuicBatchingMode::BATCHING_MODE_NONE;
}
std::vector<QuicVersion> filterSupportedVersions(
    const std::vector<QuicVersion>& versions) {
  std::vector<QuicVersion> filteredVersions;
  std::copy_if(
      versions.begin(),
      versions.end(),
      std::back_inserter(filteredVersions),
      [](auto version) {
        return version == QuicVersion::MVFST ||
            version == QuicVersion::MVFST_D24 ||
            version == QuicVersion::QUIC_DRAFT ||
            version == QuicVersion::MVFST_INVALID ||
            version == QuicVersion::MVFST_EXPERIMENTAL;
      });
  return filteredVersions;
}

folly::StringPiece writeDataReasonString(WriteDataReason reason) {
  switch (reason) {
    case WriteDataReason::PROBES:
      return "Probes";
    case WriteDataReason::ACK:
      return "Ack";
    case WriteDataReason::CRYPTO_STREAM:
      return "Crypto";
    case WriteDataReason::STREAM:
      return "Stream";
    case WriteDataReason::LOSS:
      return "Loss";
    case WriteDataReason::BLOCKED:
      return "Blocked";
    case WriteDataReason::STREAM_WINDOW_UPDATE:
      return "StreamWindowUpdate";
    case WriteDataReason::CONN_WINDOW_UPDATE:
      return "ConnWindowUpdate";
    case WriteDataReason::SIMPLE:
      return "Simple";
    case WriteDataReason::RESET:
      return "Reset";
    case WriteDataReason::PATHCHALLENGE:
      return "PathChallenge";
    case WriteDataReason::PING:
      return "Ping";
    case WriteDataReason::NO_WRITE:
      return "NoWrite";
  }
  folly::assume_unreachable();
}

folly::StringPiece writeNoWriteReasonString(NoWriteReason reason) {
  switch (reason) {
    case NoWriteReason::WRITE_OK:
      return "WriteOk";
    case NoWriteReason::EMPTY_SCHEDULER:
      return "EmptyScheduler";
    case NoWriteReason::NO_FRAME:
      return "NoFrame";
    case NoWriteReason::NO_BODY:
      return "NoBody";
    case NoWriteReason::SOCKET_FAILURE:
      return "SocketFailure";
  }
  folly::assume_unreachable();
}

folly::StringPiece readNoReadReasonString(NoReadReason reason) {
  switch (reason) {
    case NoReadReason::READ_OK:
      return "ReadOK";
    case NoReadReason::TRUNCATED:
      return "Truncated";
    case NoReadReason::EMPTY_DATA:
      return "Empty data";
    case NoReadReason::RETRIABLE_ERROR:
      return "Retriable error";
    case NoReadReason::NONRETRIABLE_ERROR:
      return "Nonretriable error";
    case NoReadReason::STALE_DATA:
      return "Stale data";
  }
  folly::assume_unreachable();
}

} // namespace quic
