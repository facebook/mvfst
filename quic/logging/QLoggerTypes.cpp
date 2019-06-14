/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
#include <quic/logging/QLoggerTypes.h>

namespace quic {

std::string toString(EventType type) {
  switch (type) {
    case EventType::PacketSent:
      return "PACKET_SENT";
    case EventType::PacketReceived:
      return "PACKET_RECEIVED";
  }
  LOG(WARNING) << "toString has unhandled QLog event type";
  return "UNKNOWN";
}
} // namespace quic
