/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/Optional.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/Types.h>

namespace quic {

struct ParsedHeaderResult {
  bool isVersionNegotiation;
  folly::Optional<PacketHeader> parsedHeader;

  ParsedHeaderResult(
      bool isVersionNegotiationIn,
      folly::Optional<PacketHeader> parsedHeaderIn);
};

folly::Expected<ParsedHeaderResult, TransportErrorCode> parseHeader(
    const folly::IOBuf& data);
} // namespace quic
