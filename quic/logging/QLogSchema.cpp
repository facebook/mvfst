/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/logging/QLogSchema.h>
#include <quic/logging/QLoggerConstants.h>

namespace quic {

folly::dynamic ReferenceTime::toDynamic() const {
  folly::dynamic obj = folly::dynamic::object;
  obj["clock_type"] = clockType;
  obj["epoch"] = epoch;

  if (!wallClockTime.empty()) {
    obj["wall_clock_time"] = wallClockTime;
  }

  return obj;
}

folly::dynamic VantagePointInfo::toDynamic() const {
  folly::dynamic obj = folly::dynamic::object;
  obj["type"] = type;

  if (!name.empty()) {
    obj["name"] = name;
  }

  return obj;
}

folly::dynamic CommonFieldsInfo::toDynamic() const {
  folly::dynamic obj = folly::dynamic::object;

  if (!odcid.empty()) {
    obj["ODCID"] = odcid;
  }

  if (!timeFormat.empty()) {
    obj["time_format"] = timeFormat;
  }

  if (!timeUnits.empty()) {
    obj["time_units"] = timeUnits;
  }

  if (!referenceTime.clockType.empty()) {
    obj["reference_time"] = referenceTime.toDynamic();
  }

  if (!protocolType.empty()) {
    obj["protocol_type"] = protocolType;
  }

  if (!groupId.empty()) {
    obj["group_id"] = groupId;
  }

  return obj;
}

VantagePointInfo createVantagePoint(
    QuicNodeType nodeType,
    const std::string& name) {
  VantagePointInfo vp;
  vp.type = (nodeType == QuicNodeType::Client)
      ? std::string(kQLogClientVantagePoint)
      : std::string(kQLogServerVantagePoint);
  vp.name = name;
  return vp;
}

ReferenceTime createSystemReferenceTime() {
  ReferenceTime rt;
  rt.clockType = std::string(kQLogClockTypeSystem);
  rt.epoch = "unknown";
  rt.wallClockTime = "";
  return rt;
}

ReferenceTime createMonotonicReferenceTime() {
  ReferenceTime rt;
  rt.clockType = std::string(kQLogClockTypeMonotonic);
  rt.epoch = "unknown";
  rt.wallClockTime = "";
  return rt;
}

} // namespace quic
