/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include "SimpleFrameFunctions.h"

#include <boost/variant/get.hpp>
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
  return folly::variant_match(
      frame,
      [&](const StopSendingFrame& frame) -> folly::Optional<QuicSimpleFrame> {
        if (!conn.streamManager->streamExists(frame.streamId)) {
          return folly::none;
        }
        return QuicSimpleFrame(frame);
      },
      [&](const MinStreamDataFrame& frame) -> folly::Optional<QuicSimpleFrame> {
        if (!conn.streamManager->streamExists(frame.streamId)) {
          return folly::none;
        }
        return QuicSimpleFrame(frame);
      },
      [&](const ExpiredStreamDataFrame& frame)
          -> folly::Optional<QuicSimpleFrame> {
        if (!conn.streamManager->streamExists(frame.streamId)) {
          return folly::none;
        }
        return QuicSimpleFrame(frame);
      },
      [&](const PathChallengeFrame& frame) -> folly::Optional<QuicSimpleFrame> {
        // Path validation timer expired, path validation failed;
        // or a different path validation was scheduled
        if (!conn.outstandingPathValidation ||
            frame != *conn.outstandingPathValidation) {
          return folly::none;
        }
        return QuicSimpleFrame(frame);
      },
      [&](const PathResponseFrame&) -> folly::Optional<QuicSimpleFrame> {
        // Do not clone PATH_RESPONSE to avoid buffering
        return folly::none;
      },
      [&](const NewConnectionIdFrame& frame)
          -> folly::Optional<QuicSimpleFrame> {
        return QuicSimpleFrame(frame);
      },
      [&](const MaxStreamsFrame& frame) -> folly::Optional<QuicSimpleFrame> {
        return QuicSimpleFrame(frame);
      },
      [&](const RetireConnectionIdFrame&) -> folly::Optional<QuicSimpleFrame> {
        // TODO junqiw
        return QuicSimpleFrame(frame);
      });
}

void updateSimpleFrameOnPacketSent(
    QuicConnectionStateBase& conn,
    const QuicSimpleFrame& simpleFrame) {
  folly::variant_match(
      simpleFrame,
      [&](const PathChallengeFrame&) {
        conn.outstandingPathValidation =
            std::move(conn.pendingEvents.pathChallenge);
        conn.pendingEvents.schedulePathValidationTimeout = true;
      },
      [&](const QuicSimpleFrame& frame) {
        auto& frames = conn.pendingEvents.frames;
        auto itr =
            find_if(frames.begin(), frames.end(), [&](QuicSimpleFrame& f) {
              return folly::variant_match(frame, [&](auto& vFrame) {
                auto fptr = boost::get<decltype(vFrame)>(&f);
                return fptr != nullptr && *fptr == vFrame;
              });
            });
        CHECK(itr != frames.end());
        frames.erase(itr);
      });
}

void updateSimpleFrameOnPacketLoss(
    QuicConnectionStateBase& conn,
    const QuicSimpleFrame& frameIn) {
  folly::variant_match(
      frameIn,
      [&](const StopSendingFrame& frame) {
        if (conn.streamManager->streamExists(frame.streamId)) {
          conn.pendingEvents.frames.push_back(frame);
        }
      },
      [&](const MinStreamDataFrame& frame) {
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (stream && stream->conn.partialReliabilityEnabled) {
          advanceCurrentReceiveOffset(stream, frame.minimumStreamOffset);
        }
      },
      [&](const ExpiredStreamDataFrame& frame) {
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (stream && stream->conn.partialReliabilityEnabled) {
          advanceMinimumRetransmittableOffset(
              stream, frame.minimumStreamOffset);
        }
      },
      [&](const PathChallengeFrame& frame) {
        if (conn.outstandingPathValidation &&
            frame == *conn.outstandingPathValidation) {
          conn.pendingEvents.pathChallenge = frame;
        }
      },
      [&](const PathResponseFrame&) {
        // Do not retransmit PATH_RESPONSE to avoid buffering
      },
      [&](const NewConnectionIdFrame& frame) {
        conn.pendingEvents.frames.push_back(frame);
      },
      [&](const MaxStreamsFrame& frame) {
        conn.pendingEvents.frames.push_back(frame);
      },
      [&](const RetireConnectionIdFrame&) {
        // TODO junqiw
      });
}

bool updateSimpleFrameOnPacketReceived(
    QuicConnectionStateBase& conn,
    const QuicSimpleFrame& frameIn,
    PacketNum packetNum,
    bool fromChangedPeerAddress) {
  return folly::variant_match(
      frameIn,
      [&](const StopSendingFrame& frame) {
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (stream) {
          invokeStreamSendStateMachine(conn, *stream, frame);
        }
        return true;
      },
      [&](const MinStreamDataFrame& frame) {
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (stream && stream->conn.partialReliabilityEnabled) {
          onRecvMinStreamDataFrame(stream, frame, packetNum);
        }
        return true;
      },
      [&](const ExpiredStreamDataFrame& frame) {
        auto stream = conn.streamManager->getStream(frame.streamId);
        if (stream && stream->conn.partialReliabilityEnabled) {
          onRecvExpiredStreamDataFrame(stream, frame);
        }
        return true;
      },
      [&](const PathChallengeFrame& frame) {
        conn.pendingEvents.frames.emplace_back(
            PathResponseFrame(frame.pathData));
        return false;
      },
      [&](const PathResponseFrame& frame) {
        // Ignore the response if outstandingPathValidation is none or
        // the path data doesn't match what's in outstandingPathValidation
        if (fromChangedPeerAddress || !conn.outstandingPathValidation ||
            frame.pathData != conn.outstandingPathValidation->pathData) {
          return false;
        }
        // TODO update source token,
        conn.outstandingPathValidation = folly::none;
        conn.pendingEvents.schedulePathValidationTimeout = false;
        conn.writableBytesLimit = folly::none;
        return false;
      },
      [&](const NewConnectionIdFrame&) {
        // TODO junqiw
        return false;
      },
      [&](const MaxStreamsFrame& maxStreamsFrame) {
        if (maxStreamsFrame.isForBidirectionalStream()) {
          conn.streamManager->setMaxLocalBidirectionalStreams(
              maxStreamsFrame.maxStreams);
        } else {
          conn.streamManager->setMaxLocalUnidirectionalStreams(
              maxStreamsFrame.maxStreams);
        }
        return true;
      },
      [&](const RetireConnectionIdFrame&) {
        // TODO junqiw
        return false;
      });
}

} // namespace quic
