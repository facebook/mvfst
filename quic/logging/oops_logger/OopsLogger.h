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
