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

#include <utility>

namespace quic::test {

/**
 * Builder for matcher for AckEvent::detailsPerStream elements.
 *
 * Reduces the amount of boilerplate code in unit tests, improving readability.
 */
struct AckEventStreamDetailsMatcherBuilder {
  using Builder = AckEventStreamDetailsMatcherBuilder;
  using RedeliveredStreamIntervals =
      AckEvent::AckPacket::StreamDetails::RedeliveredStreamIntervals;

  explicit AckEventStreamDetailsMatcherBuilder() = default;

  Builder&& setStreamID(const uint64_t streamIdIn);
  Builder&& setStreamBytesAcked(const uint64_t ackedIn);
  Builder&& setStreamBytesAckedByRetrans(const uint64_t ackedIn);
  Builder&& addRedeliveredStreamInterval(
      const RedeliveredStreamIntervals::interval_type& intervalIn);
  Builder&& addRedeliveredStreamInterval(
      const uint64_t startIn,
      const uint64_t endIn);
  Builder&& clearRedeliveredStreamIntervals();

  auto build() && {
    CHECK(maybeStreamId.has_value());
    ::testing::Matcher<AckEvent::AckPacket::StreamDetails> detailsMatcher =
        ::testing::Field(
            &AckEvent::AckPacket::StreamDetails::redeliveredStreamIntervals,
            redeliveredStreamIntervals);
    if (maybeStreamBytesAcked.has_value()) {
      detailsMatcher = ::testing::AllOf(
          detailsMatcher,
          ::testing::Field(
              &AckEvent::AckPacket::StreamDetails::streamBytesAcked,
              maybeStreamBytesAcked.value()));
    }
    if (maybeStreamBytesAckedByRetrans.has_value()) {
      detailsMatcher = ::testing::AllOf(
          detailsMatcher,
          ::testing::Field(
              &AckEvent::AckPacket::StreamDetails::streamBytesAckedByRetrans,
              maybeStreamBytesAckedByRetrans.value()));
    }
    return ::testing::Pair(maybeStreamId.value(), std::move(detailsMatcher));
  }

 private:
  Optional<uint64_t> maybeStreamId;
  Optional<uint64_t> maybeStreamBytesAcked;
  Optional<uint64_t> maybeStreamBytesAckedByRetrans;
  RedeliveredStreamIntervals redeliveredStreamIntervals;
};

} // namespace quic::test
