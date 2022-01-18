/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/codec/QuicHeaderCodec.h>

#include <quic/QuicException.h>
#include <quic/codec/Decode.h>

namespace quic {
ParsedHeaderResult::ParsedHeaderResult(
    bool isVersionNegotiationIn,
    folly::Optional<PacketHeader> parsedHeaderIn)
    : isVersionNegotiation(isVersionNegotiationIn),
      parsedHeader(std::move(parsedHeaderIn)) {
  CHECK(isVersionNegotiation || parsedHeader);
}

folly::Expected<ParsedHeaderResult, TransportErrorCode> parseHeader(
    const folly::IOBuf& data) {
  folly::io::Cursor cursor(&data);
  if (!cursor.canAdvance(sizeof(uint8_t))) {
    return folly::makeUnexpected(TransportErrorCode::FRAME_ENCODING_ERROR);
  }
  uint8_t initialByte = cursor.readBE<uint8_t>();
  if (getHeaderForm(initialByte) == HeaderForm::Long) {
    return parseLongHeader(initialByte, cursor)
        .then([](ParsedLongHeaderResult&& parsedLongHeaderResult) {
          if (parsedLongHeaderResult.isVersionNegotiation) {
            return ParsedHeaderResult(true, folly::none);
          }
          // We compensate for the type byte length by adding it back.
          DCHECK(parsedLongHeaderResult.parsedLongHeader);
          return ParsedHeaderResult(
              false,
              PacketHeader(
                  std::move(parsedLongHeaderResult.parsedLongHeader->header)));
        });
  } else {
    return parseShortHeader(initialByte, cursor).then([](ShortHeader&& header) {
      return ParsedHeaderResult(false, PacketHeader(std::move(header)));
    });
  }
}

} // namespace quic
