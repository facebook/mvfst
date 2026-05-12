/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/logging/oops_logger/OopsLogger.h>

#include <utility>

namespace proto_oops {
namespace {

std::unique_ptr<OopsLogger>& threadLocalOopsLogger() {
  thread_local std::unique_ptr<OopsLogger> logger;
  return logger;
}

} // namespace

OopsLogger* setThreadLocalOopsLoggerIfAbsent(
    std::unique_ptr<OopsLogger> logger) {
  auto& localLogger = threadLocalOopsLogger();
  if (!localLogger) {
    localLogger = std::move(logger);
  }
  return localLogger.get();
}

OopsLogger* getThreadLocalOopsLogger() {
  return threadLocalOopsLogger().get();
}

} // namespace proto_oops
