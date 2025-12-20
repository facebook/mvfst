/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/datagram/DatagramFlowManager.h>

namespace quic {

// Default priority for datagrams
const PriorityQueue::Priority kDefaultDatagramPriority{};

void DatagramFlowManager::DatagramFlowQueue::push(BufQueue buf) {
  if (multi) {
    // Already using multi queue
    multi->emplace_back(std::move(buf));
  } else if (single.empty()) {
    // First datagram
    single = std::move(buf);
  } else {
    // Transition from single to multi
    multi = std::make_unique<CircularDeque<BufQueue>>();
    multi->emplace_back(std::move(single));
    multi->emplace_back(std::move(buf));
  }
}

BufQueue& DatagramFlowManager::DatagramFlowQueue::front() {
  if (multi) {
    CHECK(!multi->empty());
    return multi->front();
  }
  CHECK(!single.empty());
  return single;
}

void DatagramFlowManager::DatagramFlowQueue::pop() {
  if (multi) {
    if (!multi->empty()) {
      multi->pop_front();
    }
    // Don't deallocate multi even if it becomes empty
  } else if (!single.empty()) {
    single = BufQueue();
  }
}

void DatagramFlowManager::addDatagram(BufQueue buf, uint32_t flowId) {
  writeBuffer_[flowId].push(std::move(buf));
  ++datagramCount_;
}

DatagramFlowManager::DatagramPopResult DatagramFlowManager::popDatagramIfFits(
    uint32_t flowId,
    uint64_t availableSpace) {
  auto it = writeBuffer_.find(flowId);
  CHECK(it != writeBuffer_.end() && !it->second.empty())
      << "popDatagramIfFits called for flow with no datagrams";

  auto& datagram = it->second.front();
  uint64_t datagramLen = datagram.chainLength();

  // Calculate overhead using stored calculator
  uint64_t overhead =
      overheadCalculator_ ? overheadCalculator_(datagramLen) : 0;
  uint64_t totalSize = datagramLen + overhead;

  if (totalSize > availableSpace) {
    return {nullptr, false, 0};
  }

  // Fits! Pop and return it
  BufPtr result = datagram.move();
  it->second.pop();
  --datagramCount_;
  bool flowEmpty = it->second.empty();
  return {std::move(result), flowEmpty, datagramLen};
}

void DatagramFlowManager::popDatagram() {
  CHECK(!writeBuffer_.empty()) << "popDatagram called with empty writeBuffer";

  auto it = writeBuffer_.begin();
  it->second.pop();
  --datagramCount_;
}

bool DatagramFlowManager::hasDatagramsForFlow(uint32_t flowId) const {
  auto it = writeBuffer_.find(flowId);
  return it != writeBuffer_.end() && !it->second.empty();
}

} // namespace quic
