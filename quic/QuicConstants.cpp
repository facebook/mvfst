/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/QuicConstants.h>

namespace quic {

QuicBatchingMode getQuicBatchingMode(uint32_t val) {
  switch (val) {
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_NONE):
      return QuicBatchingMode::BATCHING_MODE_NONE;
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_GSO):
      return QuicBatchingMode::BATCHING_MODE_GSO;
    case static_cast<uint32_t>(QuicBatchingMode::BATCHING_MODE_SENDMMSG):
      return QuicBatchingMode::BATCHING_MODE_SENDMMSG;
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
            version == QuicVersion::QUIC_DRAFT ||
            version == QuicVersion::MVFST_INVALID;
      });
  return filteredVersions;
}

std::string writeDataReasonString(WriteDataReason reason) {
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
    case WriteDataReason::NO_WRITE:
      return "NoWrite";
  }
  folly::assume_unreachable();
}

std::string writeNoWriteReasonString(NoWriteReason reason) {
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
} // namespace quic
