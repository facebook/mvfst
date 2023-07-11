/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/QuicAsyncUDPSocketWrapper.h>

namespace quic {

class QuicUDPSocketFactory {
 public:
  virtual ~QuicUDPSocketFactory() {}

  virtual std::unique_ptr<QuicAsyncUDPSocketType> make(
      folly::EventBase* evb,
      int fd) = 0;
};
} // namespace quic
