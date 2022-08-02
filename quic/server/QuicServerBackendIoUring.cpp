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
DEFINE_int32(
    qs_io_uring_use_registered_fds,
    256,
    "io_uring backend use registered fds");
DEFINE_bool(
    qs_io_uring_register_ring,
    false,
    "io_uring backend use registered ring");

namespace quic {

namespace {
std::unique_ptr<folly::EventBaseBackendBase> getEventBaseBackend() {
  if (FLAGS_qs_io_uring_capacity > 0) {
    try {
      folly::PollIoBackend::Options options;
      options.setCapacity(static_cast<size_t>(FLAGS_qs_io_uring_capacity))
          .setMaxSubmit(static_cast<size_t>(FLAGS_qs_io_uring_max_submit))
          .setMaxGet(static_cast<size_t>(FLAGS_qs_io_uring_max_get))
          .setRegisterRingFd(FLAGS_qs_io_uring_register_ring)
          .setUseRegisteredFds(FLAGS_qs_io_uring_use_registered_fds);
      if (folly::IoUringBackend::kernelSupportsRecvmsgMultishot()) {
        options.setInitialProvidedBuffers(2048, 2000);
      }
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

} // namespace

QuicServer::EventBaseBackendDetails QuicServer::getEventBaseBackendDetails() {
  EventBaseBackendDetails ret;
  ret.factory = &getEventBaseBackend;
  ret.supportsRecvmsgMultishot =
      folly::IoUringBackend::kernelSupportsRecvmsgMultishot();
  return ret;
}

} // namespace quic

#else

namespace quic {

QuicServer::EventBaseBackendDetails QuicServer::getEventBaseBackendDetails() {
  EventBaseBackendDetails ret;
  ret.factory = &folly::EventBase::getDefaultBackend;
  return ret;
}

} // namespace quic

#endif
