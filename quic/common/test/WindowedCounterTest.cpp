/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/WindowedCounter.h>

#include <quic/QuicConstants.h>

#include <gtest/gtest.h>
using namespace ::testing;

namespace quic {
namespace test {

struct TestPoint {
  TimePoint t;
  bool expect;
};

class WindowedCounterTest : public Test {
 public:
  void SetUp() override {
    reset(defaultWindow, defaultThreshold);
  }

  void reset(std::chrono::microseconds windowIn, size_t thresholdIn) {
    counter = std::make_unique<WindowedCounter<uint64_t, uint64_t>>(
        windowIn.count(), thresholdIn);
    t0 = Clock::now();
  }

  void run(const std::vector<TestPoint>& tests) {
    size_t i = 0;
    for (const auto& test : tests) {
      EXPECT_EQ(
          counter->update(std::chrono::duration_cast<std::chrono::microseconds>(
                              test.t.time_since_epoch())
                              .count()),
          test.expect)
          << "TestPoint failed: " << i;
      i++;
    }
  }

  TimePoint t0;
  std::chrono::seconds defaultWindow{10s};
  size_t defaultThreshold{3};
  std::unique_ptr<WindowedCounter<uint64_t, uint64_t>> counter;
};

TEST_F(WindowedCounterTest, MonotonicallyNewerUpdate) {
  std::vector<TestPoint> tests = {
      {t0, false},
      {t0 + 9s, false},
      {t0 + 9s + 999ms + 999us, true},
      {t0 + 10s, true},
      {t0 + 12s, true},
      {t0 + 30s, false},
      {t0 + 31s, false},
      {t0 + 32s, true},
  };
  run(tests);
}

TEST_F(WindowedCounterTest, MonotonicallyElderUpdate) {
  std::vector<TestPoint> tests = {
      {t0, false},
      {t0 - 9s, false},
      {t0 - 9s - 999ms - 999us, true},
      {t0 - 10s, true},
      {t0 - 12s, false},
      {t0 - 30s, false},
      {t0 - 31s, false},
      {t0 - 32s, false},
  };
  run(tests);
}

TEST_F(WindowedCounterTest, OscilatingUpdate) {
  std::vector<TestPoint> tests = {
      {t0, false},
      {t0 + 1s, false},
      {t0 - 9s - 1us, false},
      {t0 - 9s, true},
      {t0 - 9s, true},
      {t0 + 2s, true},
      {t0 - 9s, false},
      {t0 + 12s, false},
      {t0 + 13s, false},
      {t0 + 12s + 1ms, true},
  };
  run(tests);
}

TEST_F(WindowedCounterTest, RandomSamplesDefaultParam) {
  std::vector<TestPoint> tests = {
      {t0 + 5s, false}, {t0 + 15s, false}, {t0 + 4s, false}, {t0 + 7s, true},
      {t0 + 6s, true},  {t0 + 3s, false},  {t0 + 10s, true}, {t0 + 14s, true},
      {t0 + 2s, false}, {t0 + 7s, true},   {t0 + 20s, true}, {t0 + 18s, true},
      {t0 + 12s, true}, {t0 + 16s, true},  {t0 + 14s, true}, {t0 + 15s, true},
      {t0 + 10s, true}, {t0 + 13s, true},  {t0 + 15s, true}, {t0 + 12s, true},
      {t0 + 24s, true}, {t0 + 16s, true},  {t0 + 15s, true}, {t0 + 21s, true},
      {t0 + 17s, true}, {t0 + 20s, true},  {t0 + 26s, true}, {t0 + 21s, true},
      {t0 + 26s, true}, {t0 + 17s, true},
  };
  run(tests);
}

TEST_F(WindowedCounterTest, RandomSamplesThresholdOne) {
  reset(10s, 1);
  std::vector<TestPoint> tests = {
      {t0 + 18s, true},  {t0 + 3s, false},  {t0 + 3s, false},
      {t0 + 1s, false},  {t0 + 19s, true},  {t0 + 3s, false},
      {t0 + 13s, false}, {t0 + 26s, true},  {t0 + 20s, false},
      {t0 + 13s, false}, {t0 + 5s, false},  {t0 + 6s, false},
      {t0 + 1s, false},  {t0 + 3s, false},  {t0 + 23s, false},
      {t0 + 28s, true},  {t0 + 6s, false},  {t0 + 18s, false},
      {t0 + 18s, false}, {t0 + 28s, true},  {t0 + 2s, false},
      {t0 + 9s, false},  {t0 + 9s, false},  {t0 + 24s, false},
      {t0 + 17s, false}, {t0 + 26s, false}, {t0 + 8s, false},
      {t0 + 29s, true},  {t0 + 30s, true},  {t0 + 8s, false},
  };
  run(tests);
}

TEST_F(WindowedCounterTest, RandomSamplesLargeWindowLargeThreshold) {
  reset(20s, 5);
  std::vector<TestPoint> tests = {
      {t0 + 17s, false},  {t0 + 13s, false},  {t0 + 10s, false},
      {t0 + 13s, false},  {t0 + -10s, false}, {t0 + 21s, true},
      {t0 + -10s, false}, {t0 + 4s, true},    {t0 + -6s, false},
      {t0 + 1s, true},    {t0 + 17s, true},   {t0 + -4s, false},
      {t0 + -7s, false},  {t0 + 17s, true},   {t0 + 7s, true},
      {t0 + -4s, false},  {t0 + 11s, true},   {t0 + -2s, false},
      {t0 + 10s, true},   {t0 + 1s, true},    {t0 + 31s, true},
      {t0 + 29s, true},   {t0 + 7s, false},   {t0 + 12s, true},
      {t0 + 27s, true},   {t0 + 18s, true},   {t0 + 42s, false},
      {t0 + 13s, false},  {t0 + 25s, true},   {t0 + 18s, false},
      {t0 + 20s, false},  {t0 + 51s, false},  {t0 + 16s, false},
      {t0 + 51s, false},  {t0 + 49s, true},   {t0 + 54s, true},
      {t0 + 31s, false},  {t0 + 29s, false},  {t0 + 51s, true},
      {t0 + 35s, true},   {t0 + 22s, false},  {t0 + 30s, false},
      {t0 + 30s, false},  {t0 + 37s, true},   {t0 + 41s, true},
      {t0 + 60s, true},   {t0 + 58s, true},   {t0 + 34s, false},
      {t0 + 43s, true},   {t0 + 35s, false},  {t0 + 37s, false},
      {t0 + 64s, true},   {t0 + 40s, false},  {t0 + 40s, false},
      {t0 + 58s, true},   {t0 + 63s, true},   {t0 + 53s, true},
      {t0 + 76s, true},   {t0 + 78s, true},   {t0 + 49s, false},
      {t0 + 59s, true},   {t0 + 43s, false},  {t0 + 50s, false},
      {t0 + 45s, false},  {t0 + 61s, true},   {t0 + 83s, true},
      {t0 + 85s, false},  {t0 + 77s, true},   {t0 + 78s, true},
      {t0 + 65s, true},   {t0 + 82s, true},   {t0 + 69s, true},
      {t0 + 80s, true},   {t0 + 65s, true},   {t0 + 72s, true},
      {t0 + 58s, false},  {t0 + 64s, false},  {t0 + 97s, true},
      {t0 + 95s, true},   {t0 + 94s, true},   {t0 + 93s, true},
      {t0 + 70s, false},  {t0 + 78s, true},   {t0 + 96s, true},
      {t0 + 84s, true},   {t0 + 97s, true},   {t0 + 82s, true},
      {t0 + 88s, true},   {t0 + 78s, true},   {t0 + 79s, true},
      {t0 + 85s, true},   {t0 + 74s, false},  {t0 + 75s, false},
      {t0 + 81s, true},   {t0 + 104s, true},  {t0 + 82s, false},
      {t0 + 87s, true},   {t0 + 78s, false},  {t0 + 92s, true},
      {t0 + 106s, true},
  };
  run(tests);
}

} // namespace test
} // namespace quic
