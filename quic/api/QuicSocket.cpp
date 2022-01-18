/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicSocket.h>

namespace quic {

// required for C++14 compatibility
constexpr std::array<QuicSocket::ByteEvent::Type, 2>
    QuicSocket::ByteEvent::kByteEventTypes;

} // namespace quic
