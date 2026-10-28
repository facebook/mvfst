/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/async/ScopedEventBaseThread.h>
#include <quic/server/QuicServer.h>
#include <quic/server/QuicServerTransportFactory.h>

namespace quic {

// Owning standalone helper: worker threads plus one shared transport factory
// (concurrent make() required) around the borrowed-EventBase core. Control
// methods must not run on a worker EventBase or in its callbacks.
class ThreadedQuicServer {
 public:
  ThreadedQuicServer(
      ServerOptions options,
      std::unique_ptr<QuicServerTransportFactory> factory);

  ~ThreadedQuicServer();

  ThreadedQuicServer(const ThreadedQuicServer&) = delete;
  ThreadedQuicServer& operator=(const ThreadedQuicServer&) = delete;
  ThreadedQuicServer(ThreadedQuicServer&&) = delete;
  ThreadedQuicServer& operator=(ThreadedQuicServer&&) = delete;

  // Workers created for a requested count (0 means one per CPU) on a host
  // with numCpu CPUs, capped so every worker id fits in a connection id.
  static size_t numWorkersToCreate(size_t maxWorkers, size_t numCpu) noexcept;

  SocketAddress bind(const SocketAddress& address, size_t numWorkers = 0);
  void start();
  SocketAddress start(const SocketAddress& address, size_t numWorkers = 0);

  void shutdown();

  [[nodiscard]] QuicServer& server() {
    return *server_;
  }

  // CHECKs that bind() has completed.
  [[nodiscard]] SocketAddress getAddress() const {
    CHECK(server_);
    return server_->getAddress();
  }

  void setHostId(uint32_t hostId) {
    CHECK(server_);
    server_->setHostId(hostId);
  }

  void pauseRead() {
    CHECK(server_);
    server_->pauseRead();
  }

  [[nodiscard]] std::vector<int> getAllListeningSocketFDs() const {
    CHECK(server_);
    return server_->getAllListeningSocketFDs();
  }

  [[nodiscard]] const std::vector<folly::EventBase*>& getWorkerEvbs() const {
    return evbs_;
  }

 private:
  ServerOptions options_;
  std::unique_ptr<QuicServerTransportFactory> factory_;
  std::vector<std::unique_ptr<folly::ScopedEventBaseThread>> threads_;
  std::vector<folly::EventBase*> evbs_;
  std::unique_ptr<QuicServer> server_;
  bool bound_{false};
  bool stopped_{false};
};

} // namespace quic
