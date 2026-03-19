/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/json/json.h> // @manual=//folly:dynamic
#include <quic/QuicConstants.h>
#include <quic/common/MvfstLogging.h>
#include <quic/common/TransportKnobs.h>

namespace quic {

namespace {

constexpr uint64_t kKnobFractionMax = 100;

bool compareTransportKnobParam(
    const TransportKnobParam& lhs,
    const TransportKnobParam& rhs) {
  if (lhs.id != rhs.id) {
    return lhs.id < rhs.id;
  }
  return lhs.val < rhs.val;
}

std::optional<uint64_t> parseAsUint64(const folly::dynamic& val) {
  if (val.type() == folly::dynamic::Type::BOOL) {
    return static_cast<uint64_t>(val.asInt());
  }
  if (val.type() == folly::dynamic::Type::STRING) {
    if (const auto result = folly::tryTo<uint64_t>(val.asString())) {
      return result.value();
    }
  }
  return std::nullopt;
}

std::optional<uint64_t> parseAsFraction(const folly::dynamic& val) {
  if (val.type() != folly::dynamic::Type::STRING) {
    return std::nullopt;
  }
  auto s = val.asString();
  auto pos = s.find('/');
  if (pos == std::string::npos) {
    MVLOG_ERROR << "rtt factor knob expected format {numerator}/{denominator}";
    return std::nullopt;
  }
  uint64_t numerator =
      folly::tryTo<uint64_t>(s.substr(0, pos)).value_or(kKnobFractionMax);
  uint64_t denominator = folly::tryTo<uint64_t>(s.substr(pos + 1, s.length()))
                             .value_or(kKnobFractionMax);
  if (numerator == 0 || denominator == 0 || numerator >= kKnobFractionMax ||
      denominator >= kKnobFractionMax) {
    MVLOG_ERROR
        << "rtt factor knob numerator and denominator must be ints in range (0,"
        << kKnobFractionMax << "]";
    return std::nullopt;
  }
  return numerator * kKnobFractionMax + denominator;
}

} // namespace

Optional<TransportKnobParams> parseTransportKnobs(
    const std::string& serializedParams) {
  TransportKnobParams knobParams;
  try {
    // leave numbers as strings so that we can use uint64_t number space
    // (JSON only supports int64; numbers larger than this will trigger throw)
    folly::json::serialization_opts opts;
    opts.parse_numbers_as_strings = true;
    folly::dynamic params = folly::parseJson(serializedParams, opts);
    for (const auto& id : params.keys()) {
      auto paramId = static_cast<uint64_t>(id.asInt());
      auto val = params[id];
      auto knobId = TransportKnobParamId::_from_integral_nothrow(paramId);
      if (!knobId) {
        MVLOG_ERROR << "unknown transport knob param id " << paramId;
        return std::nullopt;
      }
      switch (*knobId) {
        case TransportKnobParamId::FORCIBLY_SET_UDP_PAYLOAD_SIZE:
        case TransportKnobParamId::CC_EXPERIMENTAL:
        case TransportKnobParamId::MAX_PACING_RATE_KNOB:
        case TransportKnobParamId::PACER_EXPERIMENTAL:
        case TransportKnobParamId::SHORT_HEADER_PADDING_KNOB:
        case TransportKnobParamId::FIXED_SHORT_HEADER_PADDING_KNOB:
        case TransportKnobParamId::KEEPALIVE_ENABLED:
        case TransportKnobParamId::PACING_TIMER_TICK:
        case TransportKnobParamId::DEFAULT_STREAM_PRIORITY:
        case TransportKnobParamId::CONNECTION_MIGRATION:
        case TransportKnobParamId::KEY_UPDATE_INTERVAL:
        case TransportKnobParamId::AUTOTUNE_RECV_STREAM_FLOW_CONTROL:
        case TransportKnobParamId::PACER_MIN_BURST_PACKETS:
        case TransportKnobParamId::MAX_WRITE_CONN_DATA_PKT_LIM:
        case TransportKnobParamId::MIN_STREAM_BUF_THRESH:
        case TransportKnobParamId::EXCESS_CWND_PCT_FOR_IMMINENT_STREAMS:
        case TransportKnobParamId::ALLOW_DUPLICATE_PROBES:
        case TransportKnobParamId::SEND_CLOSE_ON_IDLE_TIMEOUT:
        case TransportKnobParamId::MAX_PTO:
        case TransportKnobParamId::SCONE_KNOB: {
          // uint64_t knobs
          auto parsed = parseAsUint64(val);
          if (!parsed) {
            MVLOG_ERROR << "expected uint64 value for knob " << *knobId;
            return std::nullopt;
          }
          knobParams.push_back({paramId, parsed.value()});
          break;
        }
        case TransportKnobParamId::STARTUP_RTT_FACTOR_KNOB:
        case TransportKnobParamId::DEFAULT_RTT_FACTOR_KNOB: {
          // fraction string knobs ("numerator/denominator" -> packed uint64_t)
          auto factor = parseAsFraction(val);
          if (!factor) {
            return std::nullopt;
          }
          knobParams.push_back({paramId, factor.value()});
          break;
        }
        case TransportKnobParamId::CC_ALGORITHM_KNOB:
        case TransportKnobParamId::MAX_PACING_RATE_KNOB_SEQUENCED:
        case TransportKnobParamId::ACK_FREQUENCY_POLICY:
        case TransportKnobParamId::CC_CONFIG:
        case TransportKnobParamId::EGRESS_POLICER_CONFIG:
        case TransportKnobParamId::RX_PACKETS_BEFORE_ACK: {
          // string knobs
          if (val.type() != folly::dynamic::Type::STRING) {
            MVLOG_ERROR << "expected string value for knob " << *knobId;
            return std::nullopt;
          }
          knobParams.push_back({paramId, val.asString()});
          break;
        }
        case TransportKnobParamId::NO_OP: {
          if (val.type() != folly::dynamic::Type::STRING) {
            MVLOG_ERROR << "expected string value for NO_OP knob";
            return std::nullopt;
          }
          MVVLOG(4) << "Skipping over noop transport knob";
          break;
        }
        case TransportKnobParamId::UNKNOWN: {
          MVLOG_ERROR << "unknown transport knob param id " << paramId;
          return std::nullopt;
        }
      }
    }
  } catch (const std::exception& e) {
    MVLOG_ERROR << "fail to parse knobs: " << e.what();
    return std::nullopt;
  }

  std::sort(knobParams.begin(), knobParams.end(), compareTransportKnobParam);
  return knobParams;
}

} // namespace quic
