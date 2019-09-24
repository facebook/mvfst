/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/handshake/TransportParameters.h>

namespace quic {
folly::Optional<uint64_t> getIntegerParameter(
    TransportParameterId id,
    const std::vector<TransportParameter>& parameters) {
  auto it = findParameter(parameters, id);
  if (it == parameters.end()) {
    return folly::none;
  }
  auto parameterCursor = folly::io::Cursor(it->value.get());
  auto parameter = decodeQuicInteger(parameterCursor);
  if (!parameter) {
    throw QuicTransportException(
        folly::to<std::string>(
            "Failed to decode integer from TransportParameterId: ",
            static_cast<uint16_t>(id)),
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
  return parameter->first;
}

folly::Optional<StatelessResetToken> getStatelessResetTokenParameter(
    const std::vector<TransportParameter>& parameters) {
  auto it =
      findParameter(parameters, TransportParameterId::stateless_reset_token);
  if (it == parameters.end()) {
    return folly::none;
  }

  auto value = it->value->clone();
  auto range = value->coalesce();
  if (range.size() != sizeof(StatelessResetToken)) {
    throw QuicTransportException(
        "Invalid reset token", TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
  StatelessResetToken token;
  memcpy(token.data(), range.data(), range.size());
  return token;
}

TransportParameter encodeIntegerParameter(
    TransportParameterId id,
    uint64_t value) {
  folly::IOBufQueue queue{folly::IOBufQueue::cacheChainLength()};
  folly::io::QueueAppender appender(&queue, 8);
  auto encoded = encodeQuicInteger(value, appender);
  if (!encoded) {
    throw QuicTransportException(
        "Invalid integer parameter",
        TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
  }
  return {id, queue.move()};
}

TransportParameterId CustomTransportParameter::getParameterId() {
  return static_cast<TransportParameterId>(id_);
}

CustomStringTransportParameter::CustomStringTransportParameter(
    uint16_t id,
    std::string value)
    : CustomTransportParameter(id), value_(value) {}

TransportParameter CustomStringTransportParameter::encode() const {
  return {static_cast<TransportParameterId>(id_),
          folly::IOBuf::copyBuffer(value_)};
}

CustomBlobTransportParameter::CustomBlobTransportParameter(
    uint16_t id,
    std::unique_ptr<folly::IOBuf> value)
    : CustomTransportParameter(id), value_(std::move(value)) {}

TransportParameter CustomBlobTransportParameter::encode() const {
  return {static_cast<TransportParameterId>(id_), value_->clone()};
}

CustomIntegralTransportParameter::CustomIntegralTransportParameter(
    uint16_t id,
    uint64_t value)
    : CustomTransportParameter(id), value_(value) {}

TransportParameter CustomIntegralTransportParameter::encode() const {
  return encodeIntegerParameter(static_cast<TransportParameterId>(id_), value_);
}

} // namespace quic
