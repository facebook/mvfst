/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/folly_utils/BufConv.h>

namespace {
template <typename Input, typename Output>
std::unique_ptr<Output> convert(std::unique_ptr<Input>&& input) {
  Output output;
  while (input != nullptr) {
    auto rest = input->pop();
    auto rawPtr = input.release();
    auto newBuf = Output::takeOwnership(
        (void*)rawPtr->data(),
        rawPtr->length(),
        [](void*, void* userData) { delete static_cast<Input*>(userData); },
        rawPtr);
    output.appendToChain(std::move(newBuf));
    input = std::move(rest);
  }
  return output.pop();
}
} // namespace

namespace quic::follyutils {

std::unique_ptr<folly::IOBuf> toIOBuf(std::unique_ptr<quic::QuicBuffer>&& buf) {
  return convert<quic::QuicBuffer, folly::IOBuf>(std::move(buf));
}

std::unique_ptr<quic::QuicBuffer> toQuicBuf(
    std::unique_ptr<folly::IOBuf>&& buf) {
  return convert<folly::IOBuf, quic::QuicBuffer>(std::move(buf));
}

} // namespace quic::follyutils
