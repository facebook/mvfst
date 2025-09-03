/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicHeaderCodec.h>

#include <quic/codec/Decode.h>

namespace quic {
ParsedHeaderResult::ParsedHeaderResult(
    bool isVersionNegotiationIn,
    Optional<PacketHeader> parsedHeaderIn)
    : isVersionNegotiation(isVersionNegotiationIn),
      parsedHeader(std::move(parsedHeaderIn)) {
  CHECK(isVersionNegotiation || parsedHeader);
}

quic::Expected<ParsedHeaderResult, TransportErrorCode> parseHeader(
    const folly::IOBuf& data) {
  ContiguousReadCursor cursor(data.data(), data.length());
  uint8_t initialByte = 0;
  if (!cursor.tryReadBE(initialByte)) {
    return quic::make_unexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  if (getHeaderForm(initialByte) == HeaderForm::Long) {
    auto longHeaderResult = parseLongHeader(initialByte, cursor);
    if (!longHeaderResult.has_value()) {
      return quic::make_unexpected(longHeaderResult.error());
    }
    auto parsedLongHeaderResult = std::move(longHeaderResult.value());
    if (parsedLongHeaderResult.isVersionNegotiation) {
      return ParsedHeaderResult(true, std::nullopt);
    }
    // We compensate for the type byte length by adding it back.
    DCHECK(parsedLongHeaderResult.parsedLongHeader);
    return ParsedHeaderResult(
        false,
        PacketHeader(
            std::move(parsedLongHeaderResult.parsedLongHeader->header)));
  } else {
    auto shortHeaderResult = parseShortHeader(initialByte, cursor);
    if (!shortHeaderResult.has_value()) {
      return quic::make_unexpected(shortHeaderResult.error());
    }
    return ParsedHeaderResult(
        false, PacketHeader(std::move(shortHeaderResult.value())));
  }
}

} // namespace quic
