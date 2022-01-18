/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/SocketAddress.h>
#include <folly/io/async/AsyncUDPSocket.h>

#ifdef CCP_ENABLED
#include <ccp/ccp.h>
#endif

/**
 * Libccp internally allocates a fixed-size array to manage state for active
 * connections. This number defines the size of that array and thus the maximum
 * number of connections we expect to be active at any one time. Once exceeded,
 * ccp will ignore new connections.
 * TODO add error handling for this case
 */
#define MAX_CONCURRENT_CONNECTIONS_LIBCCP 1024
/**
 * This is the maximum number of datapath programs a ccp algorithm may
 * install. 10 should be sufficient, the average algorithm only needs to
 * install 1, but more complicated algorithms may use a few.
 */
#define MAX_DATAPATH_PROGRAMS_LIBCCP 10
/**
 *
 * This is the fallback timeout length, in microseconds. If libccp hasn't
 * received a response from CCP within this amount of time, it enters fallback
 * mode, and all future calls to libccp return an error until connection with
 * ccp is restored. This logic is handled within QuicCCP. Note that libccp
 * checks for this timeout using the time callbacks above, so its ability to
 * achieve this value exactly is limited by the resolution of those functions.
 */
#define FALLBACK_TIMEOUT_US_LIBCCP 1000000

namespace quic {

/**
 * Each instance of QuicServerWorker is considered a separate "datapath" by CCP
 * and thus communicates with CCP independently in order to prevent the need for
 * any coordination between workers.
 *
 * Each worker has its own corresponding instance of CCPReader to handle
 * recieving messages from CCP and dispatching them to the correct connection
 * (the cc algorithm implementation, QuicCCP, handles sending messages to CCP).
 * This CCPReader runs in the same event base as the worker.
 *
 * The current implementation assumes communication with CCP via unix sockets.
 * CCP can be configured to use other IPC mechanisms if necessary.
 *
 */
class CCPReader : public folly::AsyncUDPSocket::ReadCallback {
 public:
  explicit CCPReader();
  ~CCPReader() override;

  // Initialize state (with libccp) and send a ready message to CCP
  void try_initialize(
      folly::EventBase* evb,
      uint64_t ccpId,
      uint64_t serverId,
      uint8_t workerId);
  // Start listening on the socket
  void start();
  // Send a ready message to CCP
  int connect();
  // Pause listening on the socket
  void pauseRead();

  // Standard ReadCallback functions
  void getReadBuffer(void** buf, size_t* len) noexcept override;
  void onDataAvailable(
      const folly::SocketAddress& client,
      size_t len,
      bool truncated,
      OnDataAvailableParams params) noexcept override;
  void onReadError(const folly::AsyncSocketException& ex) noexcept override;
  void onReadClosed() noexcept override;

  // The id of the corresponding worker thread (running in the same evb)
  FOLLY_NODISCARD uint8_t getWorkerId() const noexcept;

  FOLLY_NODISCARD folly::EventBase* getEventBase() const;
  // Send a message to CCP at the unix socket /ccp/portus from our address
  // /ccp/mvfst{id}
  ssize_t writeOwnedBuffer(std::unique_ptr<folly::IOBuf> buf);

  // Get a reference to the corresponding ccp_datapath struct
  // (libccp's wrapper around a QuicServerWorker), needed
  // for interacting with libccp. This gets passed to CCP alg instances
  // by the QuicServerConnectionState object.
#ifdef CCP_ENABLED
  struct ccp_datapath* FOLLY_NULLABLE getDatapath() noexcept;
#endif

  void shutdown();

 private:
  // Bind to our unix socket address
  void bind();

  // Each ccp reader is uniquely identified by its parent
  // QuicServer/QuicServerWorker pair
  uint8_t workerId_;
  folly::SocketAddress sendAddr_;
  folly::SocketAddress recvAddr_;
  std::unique_ptr<folly::AsyncUDPSocket> ccpSocket_;
  folly::EventBase* evb_{nullptr};
  std::unique_ptr<folly::IOBuf> readBuffer_;
#ifdef CCP_ENABLED
  struct ccp_datapath ccpDatapath_;
#endif
};

} // namespace quic
