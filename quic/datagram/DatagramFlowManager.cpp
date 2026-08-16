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

void DatagramFlowManager::DatagramFlowQueue::push(QueuedDatagram datagram) {
  if (!multi) {
    if (single.buf.empty()) {
      single = std::move(datagram);
      return;
    }
    multi = std::make_unique<CircularDeque<QueuedDatagram>>();
    multi->emplace_back(std::move(single));
  }

  // Scanning from the back keeps the common append case O(1) -- O(N) only if
  // priorities arrive descending -- and makes the insert stable for equal
  // intraFlowPriority values.
  if (multi->empty() ||
      multi->back().intraFlowPriority <= datagram.intraFlowPriority) {
    multi->emplace_back(std::move(datagram));
    return;
  }
  auto pos = multi->end();
  while (pos != multi->begin()) {
    auto prev = pos;
    --prev;
    if (prev->intraFlowPriority <= datagram.intraFlowPriority) {
      break;
    }
    pos = prev;
  }
  multi->insert(pos, std::move(datagram));
}

DatagramFlowManager::QueuedDatagram&
DatagramFlowManager::DatagramFlowQueue::front() {
  if (multi) {
    CHECK(!multi->empty());
    return multi->front();
  }
  CHECK(!single.buf.empty());
  return single;
}

void DatagramFlowManager::DatagramFlowQueue::pop() {
  if (multi) {
    if (!multi->empty()) {
      multi->pop_front();
    }
    // Don't deallocate multi even if it becomes empty
  } else if (!single.buf.empty()) {
    single = QueuedDatagram();
  }
}

quic::Expected<PriorityQueue::Priority, LocalErrorCode>
DatagramFlowManager::addDatagram(
    BufQueue buf,
    uint32_t flowId,
    std::optional<PriorityQueue::Priority> priority,
    bool draining,
    std::optional<std::chrono::milliseconds> maxQueueTime,
    uint64_t intraFlowPriority) {
  auto it = writeBuffer_.find(flowId);

  // Rejected whether or not the scheduler has finished draining, so the
  // caller gets the same answer either way.
  if (it != writeBuffer_.end() && it->second.draining) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  auto& flow = writeBuffer_[flowId];
  if (draining) {
    flow.draining = true;
  }
  if (priority) {
    flow.priority = *priority;
  }
  if (maxQueueTime) {
    flow.maxQueueTime = sanitizeMaxQueueTime(*maxQueueTime);
    if (flow.maxQueueTime.count() > 0) {
      usesExpiration_ = true;
    }
  }
  QueuedDatagram queuedDatagram;
  queuedDatagram.buf = std::move(buf);
  if (flow.maxQueueTime.count() > 0) {
    queuedDatagram.enqueueTime = Clock::now();
  }
  queuedDatagram.intraFlowPriority = intraFlowPriority;
  flow.push(std::move(queuedDatagram));
  ++datagramCount_;
  return flow.priority;
}

quic::Expected<bool, LocalErrorCode> DatagramFlowManager::setFlowPriority(
    uint32_t flowId,
    PriorityQueue::Priority priority) {
  auto it = writeBuffer_.find(flowId);
  if (it == writeBuffer_.end()) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  it->second.priority = priority;
  return it->second.empty();
}

quic::Expected<void, LocalErrorCode> DatagramFlowManager::setMaxQueueTime(
    uint32_t flowId,
    std::chrono::milliseconds maxQueueTime) {
  auto it = writeBuffer_.find(flowId);
  if (it == writeBuffer_.end()) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }
  it->second.maxQueueTime = sanitizeMaxQueueTime(maxQueueTime);
  if (it->second.maxQueueTime.count() > 0) {
    usesExpiration_ = true;
  }
  return {};
}

DatagramFlowManager::DatagramPopResult DatagramFlowManager::popDatagramIfFits(
    uint32_t flowId,
    uint64_t availableSpace,
    TimePoint now) {
  auto it = writeBuffer_.find(flowId);
  CHECK(it != writeBuffer_.end() && !it->second.empty())
      << "popDatagramIfFits called for flow with no datagrams";

  auto& flow = it->second;
  uint64_t numExpired = 0;

  // Anything enqueued before this is too old. A flow with no deadline gets a
  // cutoff nothing can predate, and a datagram queued before its flow had a
  // deadline carries TimePoint::max(), so one comparison covers both cases.
  // Subtracting from now rather than adding to enqueueTime keeps that
  // sentinel from overflowing.
  const TimePoint expiryCutoff = flow.maxQueueTime.count() > 0
      ? now - flow.maxQueueTime
      : TimePoint::min();

  while (!flow.empty()) {
    auto& queuedDatagram = flow.front();

    if (expiryCutoff > queuedDatagram.enqueueTime) {
      // Expired - drop it and continue
      flow.pop();
      --datagramCount_;
      ++numExpired;
      continue;
    }

    // Found non-expired datagram - check if it fits
    uint64_t datagramLen = queuedDatagram.buf.chainLength();

    // Calculate overhead using stored calculator
    uint64_t overhead =
        overheadCalculator_ ? overheadCalculator_(datagramLen) : 0;
    uint64_t totalSize = datagramLen + overhead;

    if (totalSize > availableSpace) {
      // Doesn't fit - return without popping
      return {
          .buf = nullptr,
          .flowEmpty = false,
          .datagramLen = 0,
          .numExpired = numExpired};
    }

    // Fits! Pop and return it
    BufPtr result = queuedDatagram.buf.move();
    flow.pop();
    --datagramCount_;
    bool flowEmpty = flow.empty();
    if (flowEmpty && flow.draining) {
      writeBuffer_.erase(it);
    }
    return {
        .buf = std::move(result),
        .flowEmpty = flowEmpty,
        .datagramLen = datagramLen,
        .numExpired = numExpired};
  }

  // All datagrams expired - flow is now empty
  if (it->second.draining) {
    writeBuffer_.erase(it);
  }
  return {
      .buf = nullptr,
      .flowEmpty = true,
      .datagramLen = 0,
      .numExpired = numExpired};
}

std::optional<uint32_t> DatagramFlowManager::popDatagram() {
  CHECK(!writeBuffer_.empty()) << "popDatagram called with empty writeBuffer";

  for (auto it = writeBuffer_.begin(); it != writeBuffer_.end(); ++it) {
    // A flow can be queued with nothing in it -- created, or drained and not
    // draining -- and popping it would undercount.
    if (it->second.empty()) {
      continue;
    }
    it->second.pop();
    --datagramCount_;
    if (it->second.empty() && it->second.draining) {
      auto retiredFlowId = it->first;
      writeBuffer_.erase(it);
      return retiredFlowId;
    }
    return std::nullopt;
  }
  return std::nullopt;
}

bool DatagramFlowManager::hasDatagramsForFlow(uint32_t flowId) const {
  auto it = writeBuffer_.find(flowId);
  return it != writeBuffer_.end() && !it->second.empty();
}

std::optional<uint32_t> DatagramFlowManager::firstNonEmptyFlowId() const {
  for (const auto& [flowId, flow] : writeBuffer_) {
    if (!flow.empty()) {
      return flowId;
    }
  }
  return std::nullopt;
}

quic::Expected<void, LocalErrorCode> DatagramFlowManager::closeFlow(
    uint32_t flowId) {
  auto it = writeBuffer_.find(flowId);
  if (it == writeBuffer_.end()) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  if (it->second.empty()) {
    writeBuffer_.erase(it);
    return {};
  }

  it->second.draining = true;
  return {};
}

quic::Expected<void, LocalErrorCode> DatagramFlowManager::closeFlowNow(
    uint32_t flowId) {
  auto it = writeBuffer_.find(flowId);
  if (it == writeBuffer_.end()) {
    return quic::make_unexpected(LocalErrorCode::INVALID_OPERATION);
  }

  // Update datagram count before removing the flow
  size_t flowDatagramCount = it->second.size();
  CHECK_GE(datagramCount_, flowDatagramCount);
  datagramCount_ -= flowDatagramCount;

  // Remove the flow and drop any queued datagrams
  writeBuffer_.erase(it);
  return {};
}

} // namespace quic
