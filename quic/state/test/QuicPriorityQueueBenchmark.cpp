/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <common/init/Init.h>
#include <folly/Benchmark.h>
#include <quic/state/QuicPriorityQueue.h>
#include <vector>

using namespace std;
using namespace folly;
using namespace quic;

static inline uint8_t findNonemptyLevel(deprecated::PriorityQueue& pq) {
  for (auto i = 0; i < 16; i++) {
    deprecated::Priority pri(i / 2, i % 2);
    if (!pq.levels[deprecated::PriorityQueue::priority2index(pri)].empty()) {
      return i;
    }
  }
  return 16;
}

static inline void insert(
    deprecated::PriorityQueue& pq,
    size_t numConcurrentStreams,
    bool incremental) {
  // insert streams at various priorities
  for (size_t i = 0; i < numConcurrentStreams; i++) {
    pq.insertOrUpdate(i, deprecated::Priority(i % 8, incremental));
  }
}

static inline void processQueueIncremental(
    deprecated::PriorityQueue& pq,
    size_t numConcurrentStreams,
    size_t packetsPerStream,
    uint8_t shift) {
  CHECK_GT(packetsPerStream, 0);
  CHECK_EQ(numConcurrentStreams % 8, 0) << "requires equal streams per urgency";

  for (uint8_t urgency = 0; urgency < 8; urgency++) {
    auto levelIndex = findNonemptyLevel(pq);
    CHECK_EQ(urgency, levelIndex / 2);
    auto& level = pq.levels[levelIndex];
    level.iterator->begin();
    for (size_t i = 0;
         i < (numConcurrentStreams / 8 + shift) * packetsPerStream;
         i++) {
      (void)level.iterator->current();
      level.iterator->next();
    }
    for (size_t i = 0; i < (numConcurrentStreams / 8); i++) {
      auto id = level.iterator->current();
      level.iterator->next();
      pq.erase(id);
    }
  }
}

static inline void processQueueSequential(
    deprecated::PriorityQueue& pq,
    size_t numConcurrentStreams,
    size_t packetsPerStream) {
  CHECK_GT(packetsPerStream, 0);
  for (size_t i = 0; i < numConcurrentStreams; i++) {
    uint64_t id = 0;
    for (size_t p = 0; p < packetsPerStream; p++) {
      auto& level = pq.levels[findNonemptyLevel(pq)];
      level.iterator->begin();
      id = level.iterator->current();
      // LOG(INFO) << id;
    }
    pq.erase(id);
  }
}

static inline void benchmarkPriority(
    size_t numConcurrentStreams,
    bool incremental) {
  deprecated::PriorityQueue pq;
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
    deprecated::PriorityQueue pq;
    insert(pq, 100, false);
    pq.clear();
  }
}

BENCHMARK(insertIncremental, n) {
  // insert streams at various priorities
  for (size_t j = 0; j < n; j++) {
    deprecated::PriorityQueue pq;
    insert(pq, 100, true);
    pq.clear();
  }
}

BENCHMARK(processSequential, n) {
  // insert streams at various priorities
  size_t nStreams = 96;
  for (size_t j = 0; j < n; j++) {
    deprecated::PriorityQueue pq;
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
    deprecated::PriorityQueue pq;
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
    deprecated::PriorityQueue pq;
    BENCHMARK_SUSPEND {
      insert(pq, nStreams, false);
    }
    while (!pq.empty()) {
      auto& level = pq.levels[findNonemptyLevel(pq)];
      level.iterator->begin();
      auto id = level.iterator->current();
      pq.erase(id);
    }
  }
}

BENCHMARK(eraseIncremental, n) {
  // insert streams at various priorities
  size_t nStreams = 96;
  for (size_t j = 0; j < n; j++) {
    deprecated::PriorityQueue pq;
    BENCHMARK_SUSPEND {
      insert(pq, nStreams, true);
    }
    while (!pq.empty()) {
      auto& level = pq.levels[findNonemptyLevel(pq)];
      level.iterator->begin();
      auto id = level.iterator->current();
      pq.erase(id);
    }
  }
}

int main(int argc, char** argv) {
  facebook::initFacebook(&argc, &argv);
  runBenchmarks();
  return 0;
}
