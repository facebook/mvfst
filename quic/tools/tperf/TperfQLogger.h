/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <quic/logging/FileQLogger.h>

namespace quic {
namespace tperf {
class TperfQLogger : public FileQLogger {
 public:
  explicit TperfQLogger(std::string vantagePoint, const std::string& path);
  virtual ~TperfQLogger() override;

 private:
  std::string path_;
};
} // namespace tperf
} // namespace quic
