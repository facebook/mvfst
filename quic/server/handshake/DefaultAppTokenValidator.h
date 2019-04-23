/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/api/QuicSocket.h>

#include <fizz/server/State.h>

namespace fizz {
namespace server {
struct ResumptionState;
} // namespace server
} // namespace fizz

namespace quic {
struct QuicServerConnectionState;

class DefaultAppTokenValidator : public fizz::server::AppTokenValidator {
 public:
  explicit DefaultAppTokenValidator(
      QuicServerConnectionState* conn,
      QuicSocket::ConnectionCallback* connCallback);

  bool validate(const fizz::server::ResumptionState&) const override;

 private:
  QuicServerConnectionState* conn_;
  QuicSocket::ConnectionCallback* connCallback_;
};

} // namespace quic
