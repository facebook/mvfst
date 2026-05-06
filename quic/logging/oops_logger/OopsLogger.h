/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/logging/oops_logger/OopsFields.h>

namespace proto_oops {

class OopsLogger {
 public:
  virtual ~OopsLogger() = default;

  void log(std::string component, std::string errorMessage) {
    auto fields = OopsFieldsBuilder()
                      .setComponent(std::move(component))
                      .setErrorMessage(std::move(errorMessage))
                      .build();
    log(std::move(fields));
  }

  virtual void log(OopsFields fields) = 0;

  // Indicates if oops logging is enabled.
  [[nodiscard]] virtual bool isEnabled() const {
    return true;
  }
};

} // namespace proto_oops

// Convenience macro for OOPS logging with null-safety.
// Checks if the logger is non-null before logging.
// `loggerPtr` is any pointer-like type with bool conversion and operator->
// (e.g., shared_ptr<OopsLogger>, OopsLogger*).
#define PROTO_OOPS_LOG(loggerPtr, component, msg) \
  do {                                            \
    if (loggerPtr) {                              \
      (loggerPtr)->log((component), (msg));       \
    }                                             \
  } while (0)

// Convenience macro for conditional OOPS logging with null-safety.
// Logs only when both `cond` is true and `loggerPtr` is non-null.
// `component` is a string naming the subsystem emitting the oops.
// It is written to Scribe metadata as metadata["component"].
// `msg` is the human-readable error text for the oops event.
// It’s written to Scribe metadata as metadata["error_message"]
#define PROTO_OOPS_LOG_IF(cond, loggerPtr, component, msg) \
  do {                                                     \
    if ((cond) && (loggerPtr)) {                           \
      (loggerPtr)->log((component), (msg));                \
    }                                                      \
  } while (0)
