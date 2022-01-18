/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Benchmark.h>
#include <quic/common/CircularDeque.h>
#include <quic/common/test/TestUtils.h>
#include <deque>

namespace {
constexpr size_t kLen = 50;
template <typename T>
void prepareDeque(T& d, size_t count) {
  size_t counter = 0;
  auto buffer = quic::test::buildRandomInputData(kLen);
  while (counter++ < count) {
    d.emplace_back(buffer->clone()->moveToFbString().toStdString());
  }
}
} // namespace

BENCHMARK(deque_push_front, iters) {
  folly::BenchmarkSuspender suspender;
  std::deque<std::string> d;
  d.resize(iters);
  auto buffer = quic::test::buildRandomInputData(kLen);
  suspender.dismiss();
  while (iters--) {
    d.push_front(buffer->clone()->moveToFbString().toStdString());
  }
}

BENCHMARK(circular_deque_push_front, iters) {
  folly::BenchmarkSuspender suspender;
  quic::CircularDeque<std::string> d;
  d.resize(iters);
  auto buffer = quic::test::buildRandomInputData(kLen);
  suspender.dismiss();
  while (iters--) {
    d.push_front(buffer->clone()->moveToFbString().toStdString());
  }
}

BENCHMARK(deque_push_back, iters) {
  folly::BenchmarkSuspender suspender;
  std::deque<std::string> d;
  d.resize(iters);
  auto buffer = quic::test::buildRandomInputData(kLen);
  suspender.dismiss();
  while (iters--) {
    d.push_back(buffer->clone()->moveToFbString().toStdString());
  }
}

BENCHMARK(circular_deque_push_back, iters) {
  folly::BenchmarkSuspender suspender;
  quic::CircularDeque<std::string> d;
  d.resize(iters);
  auto buffer = quic::test::buildRandomInputData(kLen);
  suspender.dismiss();
  while (iters--) {
    d.push_back(buffer->clone()->moveToFbString().toStdString());
  }
}

BENCHMARK(deque_pop_front, iters) {
  folly::BenchmarkSuspender suspender;
  std::deque<std::string> d;
  prepareDeque(d, iters * 2);
  suspender.dismiss();
  while (iters-- && !d.empty()) {
    d.pop_front();
  }
}

BENCHMARK(circular_deque_pop_front, iters) {
  folly::BenchmarkSuspender suspender;
  quic::CircularDeque<std::string> d;
  prepareDeque(d, iters * 2);
  suspender.dismiss();
  while (iters-- && !d.empty()) {
    d.pop_front();
  }
}

BENCHMARK(deque_pop_back, iters) {
  folly::BenchmarkSuspender suspender;
  std::deque<std::string> d;
  prepareDeque(d, iters * 2);
  suspender.dismiss();
  while (iters-- && !d.empty()) {
    d.pop_back();
  }
}

BENCHMARK(circular_deque_pop_back, iters) {
  folly::BenchmarkSuspender suspender;
  quic::CircularDeque<std::string> d;
  prepareDeque(d, iters * 2);
  suspender.dismiss();
  while (iters-- && !d.empty()) {
    d.pop_back();
  }
}

BENCHMARK(deque_erase_tail, iters) {
  folly::BenchmarkSuspender suspender;
  std::deque<std::string> d;
  prepareDeque(d, iters * 2);
  suspender.dismiss();
  while (iters-- && !d.empty()) {
    d.erase(d.end() - 2, d.end());
  }
}

BENCHMARK(circular_deque_erase_tail, iters) {
  folly::BenchmarkSuspender suspender;
  quic::CircularDeque<std::string> d;
  prepareDeque(d, iters * 2);
  suspender.dismiss();
  while (iters-- && !d.empty()) {
    d.erase(d.end() - 2, d.end());
  }
}

BENCHMARK(deque_erase_head, iters) {
  folly::BenchmarkSuspender suspender;
  std::deque<std::string> d;
  prepareDeque(d, iters * 2);
  suspender.dismiss();
  while (iters-- && !d.empty()) {
    d.erase(d.begin(), d.begin() + 2);
  }
}

BENCHMARK(circular_deque_erase_head, iters) {
  folly::BenchmarkSuspender suspender;
  quic::CircularDeque<std::string> d;
  prepareDeque(d, iters * 2);
  suspender.dismiss();
  while (iters-- && !d.empty()) {
    d.erase(d.begin(), d.begin() + 2);
  }
}

BENCHMARK(deque_size, iters) {
  folly::BenchmarkSuspender suspender;
  std::deque<std::string> d;
  while (iters--) {
    d.emplace_back("This is a test string");
    suspender.dismiss();
    auto s = d.size();
    auto e = d.empty();
    folly::doNotOptimizeAway(s);
    folly::doNotOptimizeAway(e);
    suspender.rehire();
  }
}

BENCHMARK(circular_deque_size, iters) {
  folly::BenchmarkSuspender suspender;
  quic::CircularDeque<std::string> d;
  while (iters--) {
    d.emplace_back("This is a test string");
    suspender.dismiss();
    auto s = d.size();
    auto e = d.empty();
    folly::doNotOptimizeAway(s);
    folly::doNotOptimizeAway(e);
    suspender.rehire();
  }
}

BENCHMARK(deque_erase_middle, iters) {
  folly::BenchmarkSuspender suspender;
  std::deque<std::string> d;
  prepareDeque(d, iters * 2);
  suspender.dismiss();
  while (iters--) {
    d.erase(d.begin() + d.size() / 3);
  }
}

BENCHMARK(circular_deque_erase_middle, iters) {
  folly::BenchmarkSuspender suspender;
  quic::CircularDeque<std::string> d;
  prepareDeque(d, iters * 2);
  suspender.dismiss();
  while (iters--) {
    d.erase(d.begin() + d.size() / 3);
  }
}

BENCHMARK(deque_insert_middle, iters) {
  folly::BenchmarkSuspender suspender;
  std::deque<std::string> d;
  prepareDeque(d, iters / 2);
  suspender.dismiss();
  while (iters--) {
    d.insert(d.begin() + d.size() / 2, "This is a test string");
  }
}

BENCHMARK(circular_deque_insert_middle, iters) {
  folly::BenchmarkSuspender suspender;
  quic::CircularDeque<std::string> d;
  prepareDeque(d, iters / 2);
  suspender.dismiss();
  while (iters--) {
    d.insert(d.begin() + d.size() / 2, "This is a test string");
  }
}

int main(int argc, char* argv[]) {
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  folly::runBenchmarks();
  return 0;
}

/*
 * On an Intel(R) Xeon(R) CPU E5-2680 v4 @ 2.40GHz
 *
buck run @mode/opt quic/common/test:CircularDequeBench -- --bm_min_iters=100000
  ============================================================================
  quic/common/test/CircularDequeBench.cpp         relative  time/iter  iters/s
  ============================================================================
  deque_push_front                                           109.56ns    9.13M
  circular_deque_push_front                                   97.77ns   10.23M
  deque_push_back                                            106.10ns    9.43M
  circular_deque_push_back                                    99.18ns   10.08M
  deque_pop_front                                             34.43ns   29.05M
  circular_deque_pop_front                                    34.01ns   29.41M
  deque_pop_back                                              32.57ns   30.70M
  circular_deque_pop_back                                     33.32ns   30.01M
  deque_erase_tail                                            61.55ns   16.25M
  circular_deque_erase_tail                                   41.64ns   24.02M
  deque_erase_head                                            54.06ns   18.50M
  circular_deque_erase_head                                   50.11ns   19.96M
  deque_size                                                  21.56ns   46.39M
  circular_deque_size                                         21.75ns   45.98M
  deque_erase_middle                                         238.35us    4.20K
  circular_deque_erase_middle                                244.40us    4.09K
  deque_insert_middle                                        165.43us    6.04K
  circular_deque_insert_middle                               265.68us    3.76K
  ============================================================================
 */
