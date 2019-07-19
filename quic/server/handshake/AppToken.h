/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/QuicConstants.h>
#include <quic/handshake/TransportParameters.h>

#include <fizz/server/State.h>
#include <folly/IPAddress.h>
#include <folly/Optional.h>

#include <cstdint>
#include <vector>

namespace fizz {
namespace server {
struct ResumptionState;
} // namespace server
} // namespace fizz

namespace folly {
class IOBuf;
}

namespace quic {

struct AppToken {
  TicketTransportParameters transportParams;
  std::vector<folly::IPAddress> sourceAddresses;
  folly::Optional<QuicVersion> version;
  Buf appParams;
};

TicketTransportParameters createTicketTransportParameters(
    uint64_t idleTimeout,
    uint64_t maxRecvPacketSize,
    uint64_t initialMaxData,
    uint64_t initialMaxStreamDataBidiLocal,
    uint64_t initialMaxStreamDataBidiRemote,
    uint64_t initialMaxStreamDataUni,
    uint64_t initialMaxStreamsBidi,
    uint64_t initialMaxStreamsUni);

fizz::Buf encodeAppToken(const AppToken& appToken);

folly::Optional<AppToken> decodeAppToken(const folly::IOBuf& buf);

class FailingAppTokenValidator : public fizz::server::AppTokenValidator {
  bool validate(const fizz::server::ResumptionState&) override {
    return false;
  }
};

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
