/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/api/Observer.h>

#include <utility>

namespace quic {

Observer::WriteEvent::Builder&&
Observer::WriteEvent::Builder::setOutstandingPackets(
    const std::deque<OutstandingPacket>& outstandingPacketsIn) {
  maybeOutstandingPacketsRef = outstandingPacketsIn;
  return std::move(*this);
}

Observer::WriteEvent::Builder&& Observer::WriteEvent::Builder::setWriteCount(
    const uint64_t writeCountIn) {
  maybeWriteCount = writeCountIn;
  return std::move(*this);
}

Observer::WriteEvent Observer::WriteEvent::Builder::build() && {
  return WriteEvent(*this);
}

Observer::WriteEvent::WriteEvent(const WriteEvent::BuilderFields& builderFields)
    : outstandingPackets(*CHECK_NOTNULL(
          builderFields.maybeOutstandingPacketsRef.get_pointer())),
      writeCount(*CHECK_NOTNULL(builderFields.maybeWriteCount.get_pointer())) {}

Observer::AppLimitedEvent::Builder&&
Observer::AppLimitedEvent::Builder::setOutstandingPackets(
    const std::deque<OutstandingPacket>& outstandingPacketsIn) {
  maybeOutstandingPacketsRef = outstandingPacketsIn;
  return std::move(*this);
}

Observer::AppLimitedEvent::Builder&&
Observer::AppLimitedEvent::Builder::setWriteCount(const uint64_t writeCountIn) {
  maybeWriteCount = writeCountIn;
  return std::move(*this);
}

Observer::AppLimitedEvent Observer::AppLimitedEvent::Builder::build() && {
  return AppLimitedEvent(std::move(*this));
}

Observer::AppLimitedEvent::AppLimitedEvent(
    Observer::AppLimitedEvent::BuilderFields&& builderFields)
    : WriteEvent(builderFields) {}

Observer::PacketsWrittenEvent::Builder&&
Observer::PacketsWrittenEvent::Builder::setNumPacketsWritten(
    const uint64_t numPacketsWrittenIn) {
  maybeNumPacketsWritten = numPacketsWrittenIn;
  return std::move(*this);
}

Observer::PacketsWrittenEvent::Builder&&
Observer::PacketsWrittenEvent::Builder::setNumAckElicitingPacketsWritten(
    const uint64_t numAckElicitingPacketsWrittenIn) {
  maybeNumAckElicitingPacketsWritten = numAckElicitingPacketsWrittenIn;
  return std::move(*this);
}

Observer::PacketsWrittenEvent::Builder&&
Observer::PacketsWrittenEvent::Builder::setOutstandingPackets(
    const std::deque<OutstandingPacket>& outstandingPacketsIn) {
  maybeOutstandingPacketsRef = outstandingPacketsIn;
  return std::move(*this);
}

Observer::PacketsWrittenEvent::Builder&&
Observer::PacketsWrittenEvent::Builder::setWriteCount(
    const uint64_t writeCountIn) {
  maybeWriteCount = writeCountIn;
  return std::move(*this);
}

Observer::PacketsWrittenEvent
Observer::PacketsWrittenEvent::Builder::build() && {
  return PacketsWrittenEvent(std::move(*this));
}

Observer::PacketsWrittenEvent::PacketsWrittenEvent(
    Observer::PacketsWrittenEvent::BuilderFields&& builderFields)
    : WriteEvent(builderFields),
      numPacketsWritten(
          *CHECK_NOTNULL(builderFields.maybeNumPacketsWritten.get_pointer())),
      numAckElicitingPacketsWritten(*CHECK_NOTNULL(
          builderFields.maybeNumAckElicitingPacketsWritten.get_pointer())) {}

Observer::AcksProcessedEvent::Builder&&
Observer::AcksProcessedEvent::Builder::setAckEvents(
    const std::vector<AckEvent>& ackEventsIn) {
  maybeAckEventsRef = ackEventsIn;
  return std::move(*this);
}

Observer::AcksProcessedEvent Observer::AcksProcessedEvent::Builder::build() && {
  return AcksProcessedEvent(*this);
}

Observer::AcksProcessedEvent::AcksProcessedEvent(
    Observer::AcksProcessedEvent::BuilderFields builderFields)
    : ackEvents(*CHECK_NOTNULL(builderFields.maybeAckEventsRef.get_pointer())) {
}

} // namespace quic
