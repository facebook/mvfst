/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/server/handshake/AppToken.h>

#include <fizz/record/Types.h>

#include <folly/Optional.h>

namespace quic {

std::unique_ptr<folly::IOBuf> encodeAppToken(const AppToken& appToken);

folly::Optional<AppToken> decodeAppToken(const folly::IOBuf& buf);

} // namespace quic

namespace fizz {
namespace detail {

template <>
struct Reader<folly::IPAddress> {
  template <class T>
  size_t read(folly::IPAddress& ipAddress, folly::io::Cursor& cursor) {
    std::unique_ptr<folly::IOBuf> sourceAddressBuf;
    size_t len = readBuf<uint8_t>(sourceAddressBuf, cursor);
    ipAddress = folly::IPAddress::fromBinary(sourceAddressBuf->coalesce());
    return len;
  }
};

template <>
struct Writer<folly::IPAddress> {
  template <class T>
  void write(const folly::IPAddress& ipAddress, folly::io::Appender& out) {
    DCHECK(!ipAddress.empty());
    auto buf =
        folly::IOBuf::wrapBuffer(ipAddress.bytes(), ipAddress.byteCount());
    writeBuf<uint8_t>(buf, out);
  }
};

template <>
struct Sizer<folly::IPAddress> {
  template <class T>
  size_t getSize(const folly::IPAddress& ipAddress) {
    return sizeof(uint8_t) + ipAddress.byteCount();
  }
};

} // namespace detail
} // namespace fizz
