/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <common/init/Init.h>
#include <folly/Benchmark.h>
#include <quic/priority/HTTPPriorityQueue.h>
#include <vector>

using namespace std;
using namespace folly;

static inline void insert(
    quic::HTTPPriorityQueue& pq,
    size_t numConcurrentStreams,
    bool incremental) {
  // insert streams at various priorities
  for (size_t i = 0; i < numConcurrentStreams; i++) {
    pq.insertOrUpdate(
        quic::PriorityQueue::Identifier::fromStreamID(i),
        quic::HTTPPriorityQueue::Priority(i % 8, incremental));
  }
}

static inline void processQueueIncremental(
    quic::HTTPPriorityQueue& pq,
    size_t numConcurrentStreams,
    size_t packetsPerStream,
    uint8_t shift) {
  CHECK_GT(packetsPerStream, 0);
  CHECK_EQ(numConcurrentStreams % 8, 0) << "requires equal streams per urgency";

  for (uint8_t urgency = 0; urgency < 8; urgency++) {
    for (size_t i = 0;
         i < (numConcurrentStreams / 8 + shift) * (packetsPerStream - 1);
         i++) {
      (void)pq.getNextScheduledID(std::nullopt);
    }
    for (size_t i = 0; i < (numConcurrentStreams / 8); i++) {
      auto id = pq.getNextScheduledID(std::nullopt);
      // MVLOG_INFO << id.asStreamID();
      pq.erase(id);
    }
  }
}

static inline void processQueueSequential(
    quic::HTTPPriorityQueue& pq,
    size_t numConcurrentStreams,
    size_t packetsPerStream) {
  CHECK_GT(packetsPerStream, 0);
  for (size_t i = 0; i < numConcurrentStreams; i++) {
    quic::PriorityQueue::Identifier id;
    for (size_t p = 0; p < packetsPerStream; p++) {
      id = pq.getNextScheduledID(std::nullopt);
      // MVLOG_INFO << id.asStreamID();
    }
    pq.erase(id);
  }
}

static inline void benchmarkPriority(
    size_t numConcurrentStreams,
    bool incremental) {
  quic::HTTPPriorityQueue pq;
  insert(pq, numConcurrentStreams, incremental);

  size_t packetsPerStream = 4;
  if (incremental) {
    processQueueIncremental(pq, numConcurrentStreams, packetsPerStream, 1);
  } else {
    processQueueSequential(pq, numConcurrentStreams, packetsPerStream);
  }
  CHECK(pq.empty());
}

BENCHMARK(sequential, n) {
  for (size_t i = 0; i < n; i++) {
    benchmarkPriority(96, false);
  }
}

BENCHMARK(sequentialCrossover, n) {
  for (size_t i = 0; i < n; i++) {
    benchmarkPriority(40, false);
  }
}

BENCHMARK(incremental, n) {
  for (size_t i = 0; i < n; i++) {
    benchmarkPriority(96, true);
  }
}

BENCHMARK(sequential8, n) {
  for (size_t i = 0; i < n; i++) {
    benchmarkPriority(8, false);
  }
}

BENCHMARK(incremental8, n) {
  for (size_t i = 0; i < n; i++) {
    benchmarkPriority(8, true);
  }
}

BENCHMARK(insertSequential, n) {
  // insert streams at various priorities
  for (size_t j = 0; j < n; j++) {
    quic::HTTPPriorityQueue pq;
    insert(pq, 100, false);
    pq.clear();
  }
}

BENCHMARK(insertIncremental, n) {
  // insert streams at various priorities
  for (size_t j = 0; j < n; j++) {
    quic::HTTPPriorityQueue pq;
    insert(pq, 100, true);
    pq.clear();
  }
}

BENCHMARK(processSequential, n) {
  // insert streams at various priorities
  size_t nStreams = 96;
  for (size_t j = 0; j < n; j++) {
    quic::HTTPPriorityQueue pq;
    BENCHMARK_SUSPEND {
      insert(pq, nStreams, false);
    }
    processQueueSequential(pq, nStreams, 4);
  }
}

BENCHMARK(processIncremental, n) {
  // insert streams at various priorities
  size_t nStreams = 96;
  for (size_t j = 0; j < n; j++) {
    quic::HTTPPriorityQueue pq;
    BENCHMARK_SUSPEND {
      insert(pq, nStreams, true);
    }
    processQueueIncremental(pq, nStreams, 4, 0);
  }
}

BENCHMARK(eraseSequential, n) {
  // insert streams at various priorities
  size_t nStreams = 96;
  for (size_t j = 0; j < n; j++) {
    quic::HTTPPriorityQueue pq;
    BENCHMARK_SUSPEND {
      insert(pq, nStreams, false);
    }
    while (!pq.empty()) {
      pq.erase(pq.getNextScheduledID(std::nullopt));
    }
  }
}

BENCHMARK(eraseIncremental, n) {
  // insert streams at various priorities
  size_t nStreams = 96;
  for (size_t j = 0; j < n; j++) {
    quic::HTTPPriorityQueue pq;
    BENCHMARK_SUSPEND {
      insert(pq, nStreams, true);
    }
    while (!pq.empty()) {
      pq.erase(pq.getNextScheduledID(std::nullopt));
    }
  }
}

int main(int argc, char** argv) {
  facebook::initFacebook(&argc, &argv);
  runBenchmarks();
  return 0;
}
