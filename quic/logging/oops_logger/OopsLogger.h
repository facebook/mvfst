/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/logging/oops_logger/OopsFields.h>

#include <memory>

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

// Installs a logger for the current thread if none exists yet. Existing
// loggers are never replaced because accepted connections may hold raw
// pointers to the thread-local instance.
[[nodiscard]] OopsLogger* setThreadLocalOopsLoggerIfAbsent(
    std::unique_ptr<OopsLogger> logger);

[[nodiscard]] OopsLogger* getThreadLocalOopsLogger();

} // namespace proto_oops

#if defined(FOLLY_MOBILE) && FOLLY_MOBILE

// Protocol OOPS are server-side signals. Mobile builds compile shared QUIC
// sources, but should not emit OOPS or pay for callsite builders and strings.
#define PROTO_OOPS_LOG(loggerPtr, component, msg) \
  do {                                            \
  } while (0)

#define PROTO_OOPS_LOG_IF(cond, loggerPtr, component, msg) \
  do {                                                     \
  } while (0)

#define PROTO_OOPS_LOG_BUILDER(loggerPtr, builderExpr, component, msg) \
  do {                                                                 \
  } while (0)

#define PROTO_OOPS_LOG_BUILDER_IF(                \
    cond, loggerPtr, builderExpr, component, msg) \
  do {                                            \
  } while (0)

#else

// Convenience macro for OOPS logging with null-safety.
// Checks if the logger is non-null before logging.
// `loggerPtr` is any pointer-like type with bool conversion and operator->.
#define PROTO_OOPS_LOG(loggerPtr, component, msg) \
  do {                                            \
    if (loggerPtr) {                              \
      (loggerPtr)->log((component), (msg));       \
    }                                             \
  } while (0)

// Convenience macro for conditional OOPS logging with null-safety.
// Logs only when both `cond` is true and `loggerPtr` is non-null.
// `component` is a string naming the subsystem emitting the oops.
// `msg` is the human-readable error text for the oops event.
#define PROTO_OOPS_LOG_IF(cond, loggerPtr, component, msg) \
  do {                                                     \
    if ((cond) && (loggerPtr)) {                           \
      (loggerPtr)->log((component), (msg));                \
    }                                                      \
  } while (0)

// Convenience macro for OOPS logging when the caller already has an
// OopsFieldsBuilder with additional context populated.
// `builderExpr` should evaluate to an OopsFieldsBuilder; this macro adds the
// common component and error message fields before building and logging.
#define PROTO_OOPS_LOG_BUILDER(loggerPtr, builderExpr, component, msg) \
  do {                                                                 \
    if (loggerPtr) {                                                   \
      (loggerPtr)->log((builderExpr)                                   \
                           .setComponent((component))                  \
                           .setErrorMessage((msg))                     \
                           .build());                                  \
    }                                                                  \
  } while (0)

// Convenience macro for conditional OOPS logging with a pre-populated
// OopsFieldsBuilder.
// Logs only when both `cond` is true and `loggerPtr` is non-null.
#define PROTO_OOPS_LOG_BUILDER_IF(                    \
    cond, loggerPtr, builderExpr, component, msg)     \
  do {                                                \
    if ((cond) && (loggerPtr)) {                      \
      (loggerPtr)->log((builderExpr)                  \
                           .setComponent((component)) \
                           .setErrorMessage((msg))    \
                           .build());                 \
    }                                                 \
  } while (0)

#endif
