/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/lang/Assume.h>
#include <memory>

namespace folly {
class IOBuf;
}

namespace quic {
class QuicBuffer;
}

namespace quic::follyutils {

std::unique_ptr<folly::IOBuf> toIOBuf(std::unique_ptr<quic::QuicBuffer>&& buf);

std::unique_ptr<quic::QuicBuffer> toQuicBuf(
    std::unique_ptr<folly::IOBuf>&& buf);

template <typename Output, typename Input>
std::unique_ptr<Output> to(std::unique_ptr<Input>&& buf) {
  if constexpr (std::is_same_v<Input, Output>) {
    return std::move(buf);
  } else if constexpr (
      std::is_same_v<folly::IOBuf, Input> &&
      std::is_same_v<quic::QuicBuffer, Output>) {
    return toQuicBuf(std::move(buf));
  } else if constexpr (
      std::is_same_v<quic::QuicBuffer, Input> &&
      std::is_same_v<folly::IOBuf, Output>) {
    return toIOBuf(std::move(buf));
  }
  folly::assume_unreachable();
}

} // namespace quic::follyutils
