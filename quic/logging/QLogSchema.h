/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/json/dynamic.h>
#include <quic/QuicConstants.h>
#include <string>

namespace quic {

/**
 * Helper structures for IETF qlog schema (draft-ietf-quic-qlog-main-schema)
 * These structures help construct spec-compliant qlog output
 */

/**
 * ReferenceTime defines the epoch and clock type for event timestamps
 * See draft-ietf-quic-qlog-main-schema Section on time-based fields
 */
struct ReferenceTime {
  // "system" or "monotonic"
  std::string clockType;

  // RFC3339 format or "unknown"
  std::string epoch;

  // Optional wall clock time if epoch is "unknown"
  std::string wallClockTime;

  folly::dynamic toDynamic() const;
};

/**
 * VantagePointInfo represents the qlog vantage point
 * See draft-ietf-quic-qlog-main-schema Section 5 (VantagePoint)
 */
struct VantagePointInfo {
  // "client", "server", or "network"
  std::string type;

  // Optional name (e.g., hostname, server identifier)
  std::string name;

  folly::dynamic toDynamic() const;
};

/**
 * CommonFields contains fields shared by all events in a trace
 * See draft-ietf-quic-qlog-main-schema Section on CommonFields
 */
struct CommonFieldsInfo {
  // Original Destination Connection ID (as hex string)
  std::string odcid;

  // Time format: "relative_to_epoch" or "relative_to_previous_event"
  std::string timeFormat;

  // Time units (typically "us" for microseconds)
  std::string timeUnits;

  // Reference time information
  ReferenceTime referenceTime;

  // Protocol type (e.g., "QUIC_HTTP3")
  std::string protocolType;

  // Optional group_id for event grouping
  std::string groupId;

  folly::dynamic toDynamic() const;
};

/**
 * Helper to create a VantagePointInfo from QuicNodeType
 */
VantagePointInfo createVantagePoint(
    QuicNodeType nodeType,
    const std::string& name = "");

/**
 * Helper to create a ReferenceTime for system clock with unknown epoch
 */
ReferenceTime createSystemReferenceTime();

/**
 * Helper to create a ReferenceTime for monotonic clock
 */
ReferenceTime createMonotonicReferenceTime();

} // namespace quic
