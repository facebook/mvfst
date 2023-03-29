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

static inline void benchmarkPriority(quic::Priority pri, size_t n) {
  quic::PriorityQueue pq;
  size_t numConcurrentStreams = 200;
  for (size_t i = 0; i < numConcurrentStreams; i++) {
    pq.insertOrUpdate(i, pri);
  }

  size_t removeStreamId = 0;
  size_t insertStreamId = 200;
  while (n--) {
    const auto& level = pq.levels[quic::PriorityQueue::priority2index(pri)];

    // Iterate the PriorityQueue
    level.iterator->begin();
    do {
      (void)level.iterator->current();
      level.iterator->next();
    } while (!level.iterator->end());

    // Remove some old streams
    pq.erase(removeStreamId++);
    pq.erase(removeStreamId++);
    pq.erase(removeStreamId++);

    // Add some new streams
    pq.insertOrUpdate(insertStreamId++, pri);
    pq.insertOrUpdate(insertStreamId++, pri);
    pq.insertOrUpdate(insertStreamId++, pri);
  }
}

BENCHMARK(sequential, n) {
  quic::Priority pri(0, false);
  benchmarkPriority(pri, n);
}

BENCHMARK(incremental, n) {
  quic::Priority pri(0, true);
  benchmarkPriority(pri, n);
}

int main(int argc, char** argv) {
  facebook::initFacebook(&argc, &argv);
  runBenchmarks();
  return 0;
}
