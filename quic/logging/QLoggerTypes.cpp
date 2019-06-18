/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */
#include <quic/logging/QLoggerTypes.h>

namespace quic {

folly::dynamic PaddingFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::PADDING);
  return d;
}

folly::dynamic RstStreamFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::RST_STREAM);
  d["stream_id"] = streamId;
  d["error_code"] = errorCode;
  d["offset"] = offset;
  return d;
}

folly::dynamic ConnectionCloseFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::CONNECTION_CLOSE);
  d["error_code"] = toString(errorCode);
  d["reason_phrase"] = reasonPhrase;
  d["closing_frame_type"] = toString(closingFrameType);
  return d;
}

folly::dynamic ApplicationCloseFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::APPLICATION_CLOSE);
  d["error_code"] = errorCode;
  d["reason_phrase"] = reasonPhrase;
  return d;
}

folly::dynamic MaxDataFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::MAX_DATA);
  d["maximum_data"] = maximumData;
  return d;
}

folly::dynamic MaxStreamDataFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::MAX_STREAM_DATA);
  d["stream_id"] = streamId;
  d["maximum_data"] = maximumData;
  return d;
}

folly::dynamic MaxStreamsFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  FrameType type;
  if (isForBidirectional) {
    type = FrameType::MAX_STREAMS_BIDI;
  } else {
    type = FrameType::MAX_STREAMS_UNI;
  }
  d["frame_type"] = toString(type);
  d["max_streams"] = maxStreams;
  return d;
}

folly::dynamic StreamsBlockedFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  FrameType type;
  if (isForBidirectional) {
    type = FrameType::STREAMS_BLOCKED_BIDI;
  } else {
    type = FrameType::STREAMS_BLOCKED_UNI;
  }
  d["frame_type"] = toString(type);
  d["stream_limit"] = streamLimit;
  return d;
}

folly::dynamic PingFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::PING);
  return d;
}

folly::dynamic DataBlockedFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::DATA_BLOCKED);
  d["data_limit"] = dataLimit;
  return d;
}

folly::dynamic StreamDataBlockedFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::STREAM_DATA_BLOCKED);
  d["stream_id"] = streamId;
  d["data_limit"] = dataLimit;
  return d;
}

folly::dynamic StreamFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["offset"] = offset;
  d["length"] = len;
  d["fin"] = fin;
  d["id"] = streamId;
  d["frame_type"] = toString(FrameType::STREAM);
  return d;
}

folly::dynamic CryptoFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::CRYPTO_FRAME);
  d["offset"] = offset;
  d["len"] = len;
  return d;
}

folly::dynamic StopSendingFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::STOP_SENDING);
  d["stream_id"] = streamId;
  d["error_code"] = errorCode;
  return d;
}

folly::dynamic MinStreamDataFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::MIN_STREAM_DATA);
  d["stream_id"] = streamId;
  d["maximum_data"] = maximumData;
  d["minimum_stream_offset"] = minimumStreamOffset;
  return d;
}

folly::dynamic ExpiredStreamDataFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::EXPIRED_STREAM_DATA);
  d["stream_id"] = streamId;
  d["minimum_stream_offset"] = minimumStreamOffset;
  return d;
}

folly::dynamic PathChallengeFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::PATH_CHALLENGE);
  d["path_data"] = pathData;
  return d;
}

folly::dynamic PathResponseFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::PATH_RESPONSE);
  d["path_data"] = pathData;
  return d;
}

folly::dynamic NewConnectionIdFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::NEW_CONNECTION_ID);
  d["sequence"] = sequence;

  folly::dynamic dToken = folly::dynamic::array();
  for (const auto& a : token) {
    dToken.push_back(a);
  }

  d["token"] = dToken;
  return d;
}

folly::dynamic ReadAckFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  folly::dynamic ackRangeDynamic = folly::dynamic::array();

  for (const auto& b : ackBlocks) {
    folly::dynamic subArray = folly::dynamic::array(b.startPacket, b.endPacket);
    ackRangeDynamic.push_back(subArray);
  }
  d["acked_ranges"] = ackRangeDynamic;
  d["frame_type"] = toString(FrameType::ACK);
  d["ack_delay"] = ackDelay.count();
  return d;
}

folly::dynamic WriteAckFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  folly::dynamic ackRangeDynamic = folly::dynamic::array();

  for (auto it = ackBlocks.cbegin(); it != ackBlocks.cend(); ++it) {
    folly::dynamic subArray = folly::dynamic::array(it->start, it->end);
    ackRangeDynamic.push_back(subArray);
  }
  d["acked_ranges"] = ackRangeDynamic;
  d["frame_type"] = toString(FrameType::ACK);
  d["ack_delay"] = ackDelay.count();
  return d;
}

folly::dynamic ReadNewTokenFrameLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d["frame_type"] = toString(FrameType::NEW_TOKEN);
  return d;
}

folly::dynamic VersionNegotiationLog::toDynamic() const {
  folly::dynamic d = folly::dynamic::object();
  d = folly::dynamic::array();
  for (const auto& v : versions) {
    d.push_back(toString(v));
  }
  return d;
}

folly::dynamic QLogPacketEvent::toDynamic() const {
  folly::dynamic d =
      folly::dynamic::array("TRANSPORT", toString(eventType), "DEFAULT");
  folly::dynamic data = folly::dynamic::object();

  data["frames"] = folly::dynamic::array();

  for (const auto& frame : frames) {
    data["frames"].push_back(frame->toDynamic());
  }

  data["header"] = folly::dynamic::object("packet_size", packetSize)(
      "packet_number", packetNum);
  data["packet_type"] = packetType;

  d.push_back(data);
  return d;
}

folly::dynamic QLogVersionNegotiationEvent::toDynamic() const {
  folly::dynamic d =
      folly::dynamic::array("TRANSPORT", toString(eventType), "DEFAULT");
  folly::dynamic data = folly::dynamic::object();

  data["versions"] = versionLog->toDynamic();
  data["header"] = folly::dynamic::object("packet_size", packetSize);
  data["packet_type"] = packetType;

  d.push_back(data);
  return d;
}

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
