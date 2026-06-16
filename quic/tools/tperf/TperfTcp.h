/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>

namespace quic::tperf {

struct TPerfTcpClientConfig {
  std::string host;
  uint16_t port{0};
  int32_t duration{0};
};

struct TPerfTcpServerConfig {
  std::string host;
  uint16_t port{0};
  uint64_t blockSize{0};
  uint64_t writesPerLoop{0};
};

class TPerfTcpClient {
 public:
  explicit TPerfTcpClient(TPerfTcpClientConfig config);
  ~TPerfTcpClient();

  void start();

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

class TPerfTcpServer {
 public:
  explicit TPerfTcpServer(TPerfTcpServerConfig config);
  ~TPerfTcpServer();

  void start();

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace quic::tperf
