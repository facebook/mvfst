/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/QuicServer.h>

#include <folly/experimental/io/IoUringBackend.h>

#if !FOLLY_MOBILE && __has_include(<liburing.h>)

DEFINE_int32(
    qs_io_uring_capacity,
    -1,
    "io_uring backend capacity - use a > 0 value to enable it");
DEFINE_int32(qs_io_uring_max_submit, 128, "io_uring backend max submit");
DEFINE_int32(qs_io_uring_max_get, -1, "io_uring backend max get");
DEFINE_bool(
    qs_io_uring_use_registered_fds,
    false,
    "io_uring backend use registered fds");

namespace quic {
std::unique_ptr<folly::EventBaseBackendBase> QuicServer::getEventBaseBackend() {
  if (FLAGS_qs_io_uring_capacity > 0) {
    try {
      folly::PollIoBackend::Options options;
      options.setCapacity(static_cast<size_t>(FLAGS_qs_io_uring_capacity))
          .setMaxSubmit(static_cast<size_t>(FLAGS_qs_io_uring_max_submit))
          .setMaxGet(static_cast<size_t>(FLAGS_qs_io_uring_max_get))
          .setUseRegisteredFds(FLAGS_qs_io_uring_use_registered_fds);
      auto ret = std::make_unique<folly::IoUringBackend>(options);
      LOG(INFO) << "Allocating io_uring backend(" << FLAGS_qs_io_uring_capacity
                << "," << FLAGS_qs_io_uring_max_submit << ","
                << FLAGS_qs_io_uring_max_get << ","
                << FLAGS_qs_io_uring_use_registered_fds << "): " << ret.get();

      return ret;
    } catch (const std::exception& ex) {
      LOG(INFO) << "Failure creating io_uring backend: " << ex.what();
    }
  }
  return folly::EventBase::getDefaultBackend();
}
} // namespace quic

#else

namespace quic {
std::unique_ptr<folly::EventBaseBackendBase> getEventBaseBackend() {
  return folly::EventBase::getDefaultBackend();
}
} // namespace quic

#endif
