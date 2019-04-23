/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <folly/Optional.h>
#include <quic/codec/PacketNumber.h>
#include <quic/codec/Types.h>

namespace quic {

struct ParsedHeader {
  PacketHeader header;

  explicit ParsedHeader(PacketHeader headerIn);
};

struct ParsedHeaderResult {
  bool isVersionNegotiation;
  folly::Optional<ParsedHeader> parsedHeader;
  ParsedHeaderResult(
      bool isVersionNegotiationIn,
      folly::Optional<ParsedHeader> parsedHeaderIn);
};

folly::Expected<ParsedHeaderResult, TransportErrorCode> parseHeader(
    const folly::IOBuf& data);
} // namespace quic
