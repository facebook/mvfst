/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/server/handshake/AppToken.h>

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

folly::Optional<AppToken> decodeAppToken(const folly::IOBuf& buf) {
  AppToken appToken;
  folly::io::Cursor cursor(&buf);
  std::vector<fizz::Extension> extensions;
  fizz::Extension ext;
  try {
    fizz::detail::read(ext, cursor);
    extensions.push_back(std::move(ext));
    // TODO plumb version
    appToken.transportParams =
        *fizz::getTicketExtension(extensions, QuicVersion::MVFST);
    fizz::detail::readVector<uint8_t>(appToken.sourceAddresses, cursor);
    if (cursor.isAtEnd()) {
      return appToken;
    }
    fizz::detail::read(appToken.version, cursor);
    fizz::detail::readBuf<uint16_t>(appToken.appParams, cursor);
  } catch (const std::exception&) {
    return folly::none;
  }
  return appToken;
}

} // namespace quic
