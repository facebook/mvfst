/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/container/F14Map.h>
#include <folly/io/IOBuf.h>
#include <quic/QuicConstants.h>
#include <quic/common/BufUtil.h>
#include <quic/common/CircularDeque.h>
#include <quic/priority/PriorityQueue.h>
#include <chrono>

namespace quic {

// Forward declaration
extern const PriorityQueue::Priority kDefaultDatagramPriority;

/**
 * Manages buffering and scheduling of datagrams across multiple flows.
 * This class is independent of the underlying transport (QUIC, HTTP/2, etc.)
 * and can be reused for different WebTransport implementations.
 */
class DatagramFlowManager {
 public:
  // Per-flow datagram storage
  // Stores single datagram inline, allocates CircularDeque only when needed
  struct DatagramFlowQueue {
    BufQueue single;
    std::unique_ptr<CircularDeque<BufQueue>> multi;

    DatagramFlowQueue() = default;
    ~DatagramFlowQueue() = default;

    // Move-only
    DatagramFlowQueue(DatagramFlowQueue&&) = default;
    DatagramFlowQueue& operator=(DatagramFlowQueue&&) = default;
    DatagramFlowQueue(const DatagramFlowQueue&) = delete;
    DatagramFlowQueue& operator=(const DatagramFlowQueue&) = delete;

    [[nodiscard]] bool empty() const {
      return multi ? multi->empty() : single.empty();
    }

    [[nodiscard]] size_t size() const {
      return multi ? multi->size() : (single.empty() ? 0 : 1);
    }

    void push(BufQueue buf);
    BufQueue& front();
    void pop();
  };

  // Result of popping a datagram from a flow
  struct DatagramPopResult {
    BufPtr buf; // The datagram buffer (nullptr if doesn't fit or no datagram)
    bool flowEmpty; // True if the flow is now empty after pop
    uint64_t datagramLen; // Length of the datagram (0 if buf is nullptr)
  };

  DatagramFlowManager() = default;
  ~DatagramFlowManager() = default;

  // Move-only
  DatagramFlowManager(DatagramFlowManager&&) = default;
  DatagramFlowManager& operator=(DatagramFlowManager&&) = default;
  DatagramFlowManager(const DatagramFlowManager&) = delete;
  DatagramFlowManager& operator=(const DatagramFlowManager&) = delete;

  // Function type to calculate framing overhead for datagrams
  using OverheadCalculator = std::function<uint64_t(uint64_t datagramLen)>;

  /**
   * Set the overhead calculator for this flow manager.
   * This should be called once during initialization.
   */
  void setOverheadCalculator(OverheadCalculator calc) {
    overheadCalculator_ = std::move(calc);
  }

  // Helper to check if there are any pending datagrams
  [[nodiscard]] bool hasDatagramsToSend() const {
    return datagramCount_ > 0;
  }

  [[nodiscard]] size_t getDatagramCount() const {
    return datagramCount_;
  }

  /**
   * Add a datagram to a flow's write buffer.
   */
  void addDatagram(BufQueue buf, uint32_t flowId = kDefaultDatagramFlowId);

  /**
   * Pop a datagram from a flow if it fits in the available space.
   * @param flowId The flow to pop from
   * @param availableSpace Available space in bytes
   */
  DatagramPopResult popDatagramIfFits(uint32_t flowId, uint64_t availableSpace);

  /**
   * Pop a datagram from any non-empty flow.
   * Removes flow from map if it becomes empty (single datagram case).
   * Multi-datagram flows stay in the map.
   */
  void popDatagram();

  /**
   * Check if a flow exists and is not empty.
   */
  [[nodiscard]] bool hasDatagramsForFlow(uint32_t flowId) const;

 private:
  // Buffers Outgoing Datagrams per-flow
  folly::F14FastMap<uint32_t, DatagramFlowQueue> writeBuffer_;
  // Total count of datagrams across all flows
  size_t datagramCount_{0};
  // Function to calculate framing overhead for datagrams
  OverheadCalculator overheadCalculator_;
};

} // namespace quic
