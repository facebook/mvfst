/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/state/test/AckEventTestUtil.h>

namespace quic::test {

AckEventStreamDetailsMatcherBuilder&&
AckEventStreamDetailsMatcherBuilder::setStreamID(const uint64_t streamIdIn) {
  maybeStreamId = streamIdIn;
  return std::move(*this);
}

AckEventStreamDetailsMatcherBuilder&&
AckEventStreamDetailsMatcherBuilder::setStreamBytesAcked(
    const uint64_t ackedIn) {
  maybeStreamBytesAcked = ackedIn;
  return std::move(*this);
}

AckEventStreamDetailsMatcherBuilder&&
AckEventStreamDetailsMatcherBuilder::setStreamBytesAckedByRetrans(
    const uint64_t ackedByRetransIn) {
  maybeStreamBytesAckedByRetrans = ackedByRetransIn;
  return std::move(*this);
}

AckEventStreamDetailsMatcherBuilder&&
AckEventStreamDetailsMatcherBuilder::setMaybeNewDeliveryOffset(
    const folly::Optional<uint64_t>& maybeNewDeliveryOffsetIn) {
  maybeNewDeliveryOffset = maybeNewDeliveryOffsetIn;
  return std::move(*this);
}

AckEventStreamDetailsMatcherBuilder&&
AckEventStreamDetailsMatcherBuilder::addDupAckedStreamInterval(
    const DupAckedStreamIntervals::interval_type& interval) {
  dupAckedStreamIntervals.insert(interval);
  return std::move(*this);
}

AckEventStreamDetailsMatcherBuilder&&
AckEventStreamDetailsMatcherBuilder::addDupAckedStreamInterval(
    const uint64_t startIn,
    const uint64_t endIn) {
  dupAckedStreamIntervals.insert(startIn, endIn);
  return std::move(*this);
}

AckEventStreamDetailsMatcherBuilder&&
AckEventStreamDetailsMatcherBuilder::clearDupAckedStreamIntervals() {
  dupAckedStreamIntervals.clear();
  return std::move(*this);
}

} // namespace quic::test
