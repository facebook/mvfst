/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/state/AckEvent.h>

namespace quic::test {

/**
 * Builder for matcher for AckEvent::detailsPerStream elements.
 *
 * Reduces the amount of boilerplate code in unit tests, improving readability.
 */
struct AckEventStreamDetailsMatcherBuilder {
  using Builder = AckEventStreamDetailsMatcherBuilder;
  using DupAckedStreamIntervals =
      AckEvent::AckPacket::StreamDetails::DupAckedStreamIntervals;

  explicit AckEventStreamDetailsMatcherBuilder() = default;

  Builder&& setStreamID(const uint64_t streamIdIn);
  Builder&& addDupAckedStreamInterval(
      const DupAckedStreamIntervals::interval_type& intervalIn);
  Builder&& addDupAckedStreamInterval(
      const uint64_t startIn,
      const uint64_t endIn);
  Builder&& clearDupAckedStreamIntervals();

  auto build() && {
    return ::testing::Pair(
        *CHECK_NOTNULL(maybeStreamId.get_pointer()),
        ::testing::Field(
            &AckEvent::AckPacket::StreamDetails::dupAckedStreamIntervals,
            dupAckedStreamIntervals));
  }

 private:
  Optional<uint64_t> maybeStreamId;
  DupAckedStreamIntervals dupAckedStreamIntervals;
};

} // namespace quic::test
