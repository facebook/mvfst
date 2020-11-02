// Copyright 2004-present Facebook. All Rights Reserved.

#include "quic/common/TransportKnobs.h"
#include <folly/json.h>
#include <glog/logging.h>

namespace quic {

namespace {

bool compareTransportKnobParam(
    const TransportKnobParam& lhs,
    const TransportKnobParam& rhs) {
  // Sort param by id, then value
  if (lhs.id != rhs.id) {
    return lhs.id < rhs.id;
  }
  return lhs.val < rhs.val;
}

} // namespace

folly::Optional<TransportKnobParams> parseTransportKnobs(
    const std::string& serializedParams) {
  TransportKnobParams knobParams;
  try {
    folly::dynamic params = folly::parseJson(serializedParams);
    for (const auto& id : params.keys()) {
      auto paramId = folly::to<uint64_t>(id.asInt());
      auto val = params[id];
      switch (val.type()) {
        case folly::dynamic::Type::BOOL:
        case folly::dynamic::Type::INT64:
          knobParams.push_back({paramId, folly::to<uint64_t>(val.asInt())});
          continue;
        default:
          // Quic transport knob param values cannot be of type STRING, ARRAY,
          // NULLT or OBJECT
          LOG(ERROR) << "Invalid transport knob param value type";
          return folly::none;
      }
    }
  } catch (const std::exception& e) {
    LOG(ERROR) << "fail to parse knobs: " << e.what();
    return folly::none;
  }

  std::sort(knobParams.begin(), knobParams.end(), compareTransportKnobParam);
  return knobParams;
}

} // namespace quic
