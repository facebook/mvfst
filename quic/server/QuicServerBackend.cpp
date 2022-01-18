/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/QuicServer.h>

namespace quic {
std::unique_ptr<folly::EventBaseBackendBase> QuicServer::getEventBaseBackend() {
  return folly::EventBase::getDefaultBackend();
}
} // namespace quic
