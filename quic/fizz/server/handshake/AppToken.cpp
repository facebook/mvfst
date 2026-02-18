/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/server/handshake/AppToken.h>

#include <quic/QuicConstants.h>
#include <quic/fizz/handshake/FizzTransportParameters.h>

#include <fizz/server/State.h>

#include <vector>

namespace quic {

std::unique_ptr<folly::IOBuf> encodeAppToken(const AppToken& appToken) {
  auto buf = folly::IOBuf::create(20);
  folly::io::Appender appender(buf.get(), 20);
  auto ext = encodeExtension(appToken.transportParams, QuicVersion::MVFST);
  fizz::detail::write(ext, appender);
  fizz::detail::writeVector<uint8_t>(appToken.sourceAddresses, appender);
  fizz::detail::write(appToken.version, appender);
  fizz::detail::writeBuf<uint16_t>(appToken.appParams, appender);
  return buf;
}

Optional<AppToken> decodeAppToken(const folly::IOBuf& buf) {
  AppToken appToken;
  Cursor cursor(&buf);
  std::vector<fizz::Extension> extensions;
  fizz::Extension ext;
  try {
    size_t len;
    fizz::Error err;
    FIZZ_THROW_ON_ERROR(fizz::detail::read(len, err, ext, cursor), err);
    extensions.push_back(std::move(ext));
    // TODO plumb version
    appToken.transportParams =
        *fizz::getTicketExtension(extensions, QuicVersion::MVFST);
    FIZZ_THROW_ON_ERROR(
        fizz::detail::readVector<uint8_t>(
            len, err, appToken.sourceAddresses, cursor),
        err);
    if (cursor.isAtEnd()) {
      return appToken;
    }
    FIZZ_THROW_ON_ERROR(
        fizz::detail::read(len, err, appToken.version, cursor), err);
    fizz::detail::readBuf<uint16_t>(appToken.appParams, cursor);
  } catch (const std::exception&) {
    return std::nullopt;
  }
  return appToken;
}

} // namespace quic
