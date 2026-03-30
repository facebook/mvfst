/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/logging/oops_logger/OopsLogger.h>

#include <fmt/core.h>
#include <folly/experimental/symbolizer/Symbolizer.h>
#include <quic/common/MvfstLogging.h>

namespace proto_oops {

// Use only for debugging. Symbolizes inline which is expensive and logs to
// GLOG
class GlogOopsLogger : public OopsLogger {
 public:
  GlogOopsLogger() = default;
  ~GlogOopsLogger() override = default;

  void log(OopsFields fields) override {
    auto epochSecs = std::chrono::duration_cast<std::chrono::seconds>(
                         fields.timestamp.time_since_epoch())
                         .count();

    auto msg = fmt::format(
        "OOPS: component={}, timestamp={}, error={}",
        fields.component,
        epochSecs,
        fields.errorMessage);

    if (fields.version.has_value()) {
      msg += fmt::format(", version={}", fields.version.value());
    }
    if (fields.alpn.has_value()) {
      msg += fmt::format(", alpn={}", fields.alpn.value());
    }
    if (fields.connectionId.has_value()) {
      msg += fmt::format(", connId={}", fields.connectionId.value());
    }
    if (fields.streamId.has_value()) {
      msg += fmt::format(", streamId={}", fields.streamId.value());
    }
    if (fields.errorCode.has_value()) {
      msg += fmt::format(", errorCode={}", fields.errorCode.value());
    }
    if (fields.exceptionType.has_value()) {
      msg += fmt::format(", exceptionType={}", fields.exceptionType.value());
    }

    auto backtrace = folly::symbolizer::getStackTraceStr();
    if (!backtrace.empty()) {
      msg += fmt::format("\nBacktrace:\n{}", backtrace);
    }

    MVLOG_ERROR << msg;
  }
};

} // namespace proto_oops
