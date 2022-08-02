/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/QuicServer.h>

namespace quic {

QuicServer::EventBaseBackendDetails QuicServer::getEventBaseBackendDetails() {
  EventBaseBackendDetails ret;
  ret.factory = &folly::EventBase::getDefaultBackend;
  return ret;
}

} // namespace quic
