/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include "SimpleFrameFunctions.h"

#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>

namespace quic {
void sendSimpleFrame(QuicConnectionStateBase& conn, QuicSimpleFrame frame) {
  conn.pendingEvents.frames.emplace_back(std::move(frame));
}

void updateSimpleFrameOnAck(
    QuicConnectionStateBase& /*conn*/,
    const QuicSimpleFrame& /*frame*/) {
  // TODO implement.
}

folly::Optional<QuicSimpleFrame> updateSimpleFrameOnPacketClone(
    QuicConnectionStateBase& conn,
    const QuicSimpleFrame& frame) {
  switch (frame.type()) {
    case QuicSimpleFrame::Type::StopSendingFrame_E:
      if (!conn.streamManager->streamExists(
              frame.asStopSendingFrame()->streamId)) {
        return folly::none;
      }
      return QuicSimpleFrame(frame);
    case QuicSimpleFrame::Type::MinStreamDataFrame_E:
      if (!conn.streamManager->streamExists(
              frame.asMinStreamDataFrame()->streamId)) {
        return folly::none;
      }
      return QuicSimpleFrame(frame);
    case QuicSimpleFrame::Type::ExpiredStreamDataFrame_E:
      if (!conn.streamManager->streamExists(
              frame.asExpiredStreamDataFrame()->streamId)) {
        return folly::none;
      }
      return QuicSimpleFrame(frame);
    case QuicSimpleFrame::Type::PathChallengeFrame_E:
      // Path validation timer expired, path validation failed;
      // or a different path validation was scheduled
      if (!conn.outstandingPathValidation ||
          *frame.asPathChallengeFrame() != *conn.outstandingPathValidation) {
        return folly::none;
      }
      return QuicSimpleFrame(frame);
    case QuicSimpleFrame::Type::PathResponseFrame_E:
      // Do not clone PATH_RESPONSE to avoid buffering
      return folly::none;
    case QuicSimpleFrame::Type::NewConnectionIdFrame_E:
    case QuicSimpleFrame::Type::MaxStreamsFrame_E:
    case QuicSimpleFrame::Type::RetireConnectionIdFrame_E:
      // TODO junqiw
      return QuicSimpleFrame(frame);
  }
  folly::assume_unreachable();
}

void updateSimpleFrameOnPacketSent(
    QuicConnectionStateBase& conn,
    const QuicSimpleFrame& simpleFrame) {
  switch (simpleFrame.type()) {
    case QuicSimpleFrame::Type::PathChallengeFrame_E:
      conn.outstandingPathValidation =
          std::move(conn.pendingEvents.pathChallenge);
      conn.pendingEvents.schedulePathValidationTimeout = true;
      break;
    default: {
      auto& frames = conn.pendingEvents.frames;
      auto itr = std::find(frames.begin(), frames.end(), simpleFrame);
      CHECK(itr != frames.end());
      frames.erase(itr);
      break;
    }
  }
}

void updateSimpleFrameOnPacketLoss(
    QuicConnectionStateBase& conn,
    const QuicSimpleFrame& frame) {
  switch (frame.type()) {
    case QuicSimpleFrame::Type::StopSendingFrame_E: {
      const StopSendingFrame& stopSendingFrame = *frame.asStopSendingFrame();
      if (conn.streamManager->streamExists(stopSendingFrame.streamId)) {
        conn.pendingEvents.frames.push_back(stopSendingFrame);
      }
      break;
    }
    case QuicSimpleFrame::Type::MinStreamDataFrame_E: {
      const MinStreamDataFrame& minStreamData = *frame.asMinStreamDataFrame();
      auto stream = conn.streamManager->getStream(minStreamData.streamId);
      if (stream && stream->conn.partialReliabilityEnabled) {
        advanceCurrentReceiveOffset(stream, minStreamData.minimumStreamOffset);
      }
      break;
    }
    case QuicSimpleFrame::Type::ExpiredStreamDataFrame_E: {
      const ExpiredStreamDataFrame& expiredFrame =
          *frame.asExpiredStreamDataFrame();
      auto stream = conn.streamManager->getStream(expiredFrame.streamId);
      if (stream && stream->conn.partialReliabilityEnabled) {
        advanceMinimumRetransmittableOffset(
            stream, expiredFrame.minimumStreamOffset);
      }
      break;
    }
    case QuicSimpleFrame::Type::PathChallengeFrame_E: {
      const PathChallengeFrame& pathChallenge = *frame.asPathChallengeFrame();
      if (conn.outstandingPathValidation &&
          pathChallenge == *conn.outstandingPathValidation) {
        conn.pendingEvents.pathChallenge = pathChallenge;
      }
      break;
    }
    case QuicSimpleFrame::Type::PathResponseFrame_E: {
      // Do not retransmit PATH_RESPONSE to avoid buffering
      break;
    }
    case QuicSimpleFrame::Type::NewConnectionIdFrame_E:
    case QuicSimpleFrame::Type::MaxStreamsFrame_E:
    case QuicSimpleFrame::Type::RetireConnectionIdFrame_E:
      conn.pendingEvents.frames.push_back(frame);
      break;
  }
}

bool updateSimpleFrameOnPacketReceived(
    QuicConnectionStateBase& conn,
    const QuicSimpleFrame& frame,
    PacketNum packetNum,
    bool fromChangedPeerAddress) {
  switch (frame.type()) {
    case QuicSimpleFrame::Type::StopSendingFrame_E: {
      const StopSendingFrame& stopSending = *frame.asStopSendingFrame();
      auto stream = conn.streamManager->getStream(stopSending.streamId);
      if (stream) {
        invokeStreamSendStateMachine(conn, *stream, stopSending);
      }
      return true;
    }
    case QuicSimpleFrame::Type::MinStreamDataFrame_E: {
      const MinStreamDataFrame& minStreamData = *frame.asMinStreamDataFrame();
      auto stream = conn.streamManager->getStream(minStreamData.streamId);
      if (stream && stream->conn.partialReliabilityEnabled) {
        onRecvMinStreamDataFrame(stream, minStreamData, packetNum);
      }
      return true;
    }
    case QuicSimpleFrame::Type::ExpiredStreamDataFrame_E: {
      const ExpiredStreamDataFrame& expiredStreamData =
          *frame.asExpiredStreamDataFrame();
      auto stream = conn.streamManager->getStream(expiredStreamData.streamId);
      if (stream && stream->conn.partialReliabilityEnabled) {
        onRecvExpiredStreamDataFrame(stream, expiredStreamData);
      }
      return true;
    }
    case QuicSimpleFrame::Type::PathChallengeFrame_E: {
      const PathChallengeFrame& pathChallenge = *frame.asPathChallengeFrame();
      conn.pendingEvents.frames.emplace_back(
          PathResponseFrame(pathChallenge.pathData));
      return false;
    }
    case QuicSimpleFrame::Type::PathResponseFrame_E: {
      const PathResponseFrame& pathResponse = *frame.asPathResponseFrame();
      // Ignore the response if outstandingPathValidation is none or
      // the path data doesn't match what's in outstandingPathValidation
      if (fromChangedPeerAddress || !conn.outstandingPathValidation ||
          pathResponse.pathData != conn.outstandingPathValidation->pathData) {
        return false;
      }
      // TODO update source token,
      conn.outstandingPathValidation = folly::none;
      conn.pendingEvents.schedulePathValidationTimeout = false;
      conn.writableBytesLimit = folly::none;
      return false;
    }
    case QuicSimpleFrame::Type::NewConnectionIdFrame_E: {
      // TODO junqiw
      return false;
    }
    case QuicSimpleFrame::Type::MaxStreamsFrame_E: {
      const MaxStreamsFrame& maxStreamsFrame = *frame.asMaxStreamsFrame();
      if (maxStreamsFrame.isForBidirectionalStream()) {
        conn.streamManager->setMaxLocalBidirectionalStreams(
            maxStreamsFrame.maxStreams);
      } else {
        conn.streamManager->setMaxLocalUnidirectionalStreams(
            maxStreamsFrame.maxStreams);
      }
      return true;
    }
    case QuicSimpleFrame::Type::RetireConnectionIdFrame_E: {
      // TODO junqiw
      return false;
    }
  }
  folly::assume_unreachable();
}

} // namespace quic
