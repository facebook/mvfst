/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicConstants.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/stream/StreamSendHandlers.h>

namespace quic {
void sendSimpleFrame(QuicConnectionStateBase& conn, QuicSimpleFrame frame) {
  CHECK(frame.type() != QuicSimpleFrame::Type::PathChallengeFrame);
  CHECK(frame.type() != QuicSimpleFrame::Type::PathResponseFrame);
  conn.pendingEvents.frames.emplace_back(std::move(frame));
}

Optional<QuicSimpleFrame> updateSimpleFrameOnPacketClone(
    QuicConnectionStateBase& conn,
    PathIdType pathId,
    const QuicSimpleFrame& frame) {
  switch (frame.type()) {
    case QuicSimpleFrame::Type::StopSendingFrame:
      if (!conn.streamManager->streamExists(
              frame.asStopSendingFrame()->streamId)) {
        return std::nullopt;
      }
      return QuicSimpleFrame(frame);
    case QuicSimpleFrame::Type::PathChallengeFrame: {
      // Path challenges should only be cloned if we're on
      // the same path and the path has not been validated yet.
      // TODO: Should we disable probes completely if we only have packets for
      // alternate paths?
      const PathChallengeFrame& pathChallenge = *frame.asPathChallengeFrame();
      auto pathInfo =
          conn.pathManager->getPathByChallengeData(pathChallenge.pathData);
      if (!pathInfo || pathInfo->status != PathStatus::Validating ||
          pathInfo->id != conn.currentPathId) {
        return std::nullopt;
      }
      return QuicSimpleFrame(frame);
    }
    case QuicSimpleFrame::Type::PathResponseFrame: {
      // Path responses should only be cloned if we're on
      // the same path and the path has not failed validation.
      // TODO: Should we disable probes completely if we only have packets for
      // alternate paths?
      auto pathInfo = conn.pathManager->getPath(pathId);
      if (!pathInfo || pathInfo->status == PathStatus::NotValid ||
          pathInfo->id != conn.currentPathId) {
        return std::nullopt;
      }
      return QuicSimpleFrame(frame);
    }
    case QuicSimpleFrame::Type::NewConnectionIdFrame:
    case QuicSimpleFrame::Type::MaxStreamsFrame:
    case QuicSimpleFrame::Type::HandshakeDoneFrame:
    case QuicSimpleFrame::Type::KnobFrame:
    case QuicSimpleFrame::Type::AckFrequencyFrame:
    case QuicSimpleFrame::Type::RetireConnectionIdFrame:
    case QuicSimpleFrame::Type::NewTokenFrame:
      // TODO junqiw
      return QuicSimpleFrame(frame);
  }
  folly::assume_unreachable();
}

void updateSimpleFrameOnPacketSent(
    QuicConnectionStateBase& conn,
    PathIdType pathId,
    const QuicSimpleFrame& simpleFrame) {
  switch (simpleFrame.type()) {
    case QuicSimpleFrame::Type::PathChallengeFrame: {
      const PathChallengeFrame& pathChallenge =
          *simpleFrame.asPathChallengeFrame();
      conn.pathManager->onPathChallengeSent(pathChallenge);

      auto it = conn.pendingEvents.pathChallenges.find(pathId);
      if (it != conn.pendingEvents.pathChallenges.end() &&
          it->second.pathData == pathChallenge.pathData) {
        conn.pendingEvents.pathChallenges.erase(it);
      }
      break;
    }
    case QuicSimpleFrame::Type::PathResponseFrame: {
      const PathResponseFrame& pathResponse =
          *simpleFrame.asPathResponseFrame();

      auto it = conn.pendingEvents.pathResponses.find(pathId);
      if (it != conn.pendingEvents.pathResponses.end() &&
          it->second.pathData == pathResponse.pathData) {
        conn.pendingEvents.pathResponses.erase(it);
      }
      break;
    }
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
    PathIdType pathId,
    const QuicSimpleFrame& frame) {
  switch (frame.type()) {
    case QuicSimpleFrame::Type::StopSendingFrame: {
      const StopSendingFrame& stopSendingFrame = *frame.asStopSendingFrame();
      if (conn.streamManager->streamExists(stopSendingFrame.streamId)) {
        conn.pendingEvents.frames.emplace_back(stopSendingFrame);
      }
      break;
    }
    case QuicSimpleFrame::Type::PathChallengeFrame: {
      const PathChallengeFrame& pathChallenge = *frame.asPathChallengeFrame();
      // Find the path by the challenge data rather than the path id. This
      // avoids having to do extra checks to confirm the challenge data in the
      // frame is still current for the path.
      auto maybePath =
          conn.pathManager->getPathByChallengeData(pathChallenge.pathData);
      if (maybePath && maybePath->status == PathStatus::Validating) {
        // This path is still pending validation. We need to resend this path
        // challenge frame
        conn.pendingEvents.pathChallenges.insert_or_assign(
            maybePath->id, pathChallenge);
      }
      break;
    }
    case QuicSimpleFrame::Type::PathResponseFrame: {
      auto maybePath = conn.pathManager->getPath(pathId);
      // Retransmit the path response only if we are still validating or have
      // validated the path. If it's not valid, we shouldn't retransmit the
      // path response.
      if (maybePath && maybePath->status != PathStatus::NotValid) {
        const PathResponseFrame& pathResponse = *frame.asPathResponseFrame();
        conn.pendingEvents.pathResponses.insert_or_assign(pathId, pathResponse);
      }
      break;
    }
    case QuicSimpleFrame::Type::HandshakeDoneFrame: {
      conn.pendingEvents.frames.emplace_back(*frame.asHandshakeDoneFrame());
      break;
    }
    case QuicSimpleFrame::Type::NewConnectionIdFrame:
    // If a NEW_CONNECTION_ID frame is lost, transmit it on the primary path.
    case QuicSimpleFrame::Type::MaxStreamsFrame:
    case QuicSimpleFrame::Type::RetireConnectionIdFrame:
    case QuicSimpleFrame::Type::KnobFrame:
    case QuicSimpleFrame::Type::AckFrequencyFrame:
    case QuicSimpleFrame::Type::NewTokenFrame:
      conn.pendingEvents.frames.push_back(frame);
      break;
  }
}

quic::Expected<bool, QuicError> updateSimpleFrameOnPacketReceived(
    QuicConnectionStateBase& conn,
    PathIdType pathId,
    const QuicSimpleFrame& frame,
    const ConnectionId& dstConnId) {
  switch (frame.type()) {
    case QuicSimpleFrame::Type::StopSendingFrame: {
      const StopSendingFrame& stopSending = *frame.asStopSendingFrame();
      auto streamResult = conn.streamManager->getStream(stopSending.streamId);
      if (!streamResult.has_value()) {
        return quic::make_unexpected(streamResult.error());
      }
      auto& stream = streamResult.value();
      if (stream) {
        auto result = sendStopSendingSMHandler(*stream, stopSending);
        if (!result.has_value()) {
          return quic::make_unexpected(result.error());
        }
      }
      return true;
    }
    case QuicSimpleFrame::Type::PathChallengeFrame: {
      // TODO: JBESHAY MIGRATION - Rotate connection IDs in the transport where
      // paths will be managed.
      const PathChallengeFrame& pathChallenge = *frame.asPathChallengeFrame();
      conn.pendingEvents.pathResponses.insert_or_assign(
          pathId, PathResponseFrame(pathChallenge.pathData));
      return false;
    }
    case QuicSimpleFrame::Type::PathResponseFrame: {
      const PathResponseFrame& pathResponse = *frame.asPathResponseFrame();
      auto validatedPath =
          conn.pathManager->onPathResponseReceived(pathResponse, pathId);

      // If this is the current path that just got validated, we should update
      // the RTT.
      if (validatedPath && validatedPath->id == conn.currentPathId) {
        CHECK(validatedPath->rttSample.has_value());
        updateRtt(conn, validatedPath->rttSample.value(), 0us);
      }

      return false;
    }
    case QuicSimpleFrame::Type::NewConnectionIdFrame: {
      const NewConnectionIdFrame& newConnectionId =
          *frame.asNewConnectionIdFrame();

      // TODO vchynaro Ensure we ignore smaller subsequent retirePriorTos
      // than the largest seen so far.
      if (newConnectionId.retirePriorTo > newConnectionId.sequenceNumber) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "Retire prior to greater than sequence number"));
      }

      for (const auto& existingPeerConnIdData : conn.peerConnectionIds) {
        if (existingPeerConnIdData.connId == newConnectionId.connectionId) {
          if (existingPeerConnIdData.sequenceNumber !=
              newConnectionId.sequenceNumber) {
            return quic::make_unexpected(QuicError(
                TransportErrorCode::PROTOCOL_VIOLATION,
                "Repeated connection id with different sequence number."));
          } else {
            // No-op on repeated conn id.
            return false;
          }
        }
      }

      // PeerConnectionIds holds ALL peer's connection ids
      // (initial + NEW_CONNECTION_ID).
      // If using 0-len peer cid then this would be the only element.
      auto peerConnId =
          (conn.nodeType == QuicNodeType::Client ? conn.serverConnectionId
                                                 : conn.clientConnectionId);
      if (!peerConnId || peerConnId->size() == 0) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "Endpoint is already using 0-len connection ids."));
      }
      // TODO vchynaro Implement retire_prior_to logic

      // selfActiveConnectionIdLimit represents the active_connection_id_limit
      // transport parameter which is the maximum amount of connection ids
      // provided by NEW_CONNECTION_ID frames. We add 1 to represent the initial
      // cid.
      if (conn.peerConnectionIds.size() ==
          conn.transportSettings.selfActiveConnectionIdLimit + 1) {
        // Unspec'd as of d-23 if a server doesn't respect the
        // active_connection_id_limit. Ignore frame.
        return false;
      }
      conn.peerConnectionIds.emplace_back(
          newConnectionId.connectionId,
          newConnectionId.sequenceNumber,
          newConnectionId.token);
      return false;
    }
    case QuicSimpleFrame::Type::MaxStreamsFrame: {
      const MaxStreamsFrame& maxStreamsFrame = *frame.asMaxStreamsFrame();
      if (maxStreamsFrame.isForBidirectionalStream()) {
        auto result = conn.streamManager->setMaxLocalBidirectionalStreams(
            maxStreamsFrame.maxStreams);
        if (!result.has_value()) {
          return quic::make_unexpected(result.error());
        }
      } else {
        auto result = conn.streamManager->setMaxLocalUnidirectionalStreams(
            maxStreamsFrame.maxStreams);
        if (!result.has_value()) {
          return quic::make_unexpected(result.error());
        }
      }
      return true;
    }
    case QuicSimpleFrame::Type::RetireConnectionIdFrame: {
      const auto& curNodeConnId = conn.nodeType == QuicNodeType::Server
          ? conn.serverConnectionId
          : conn.clientConnectionId;
      if (!curNodeConnId || curNodeConnId->size() == 0) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "Peer issued RETIRE_CONNECTION_ID_FRAME to endpoint using 0-len connection ids."));
      }
      const RetireConnectionIdFrame& retireConnIdFrame =
          *frame.asRetireConnectionIdFrame();
      auto& selfConnIds = conn.selfConnectionIds;
      // search for conn id corresponding to sequence number
      auto it = std::find_if(
          selfConnIds.cbegin(),
          selfConnIds.cend(),
          [&](const ConnectionIdData& connId) {
            return retireConnIdFrame.sequenceNumber == connId.sequenceNumber;
          });
      if (it == selfConnIds.end()) {
        // ignore invalid seq no
        return true;
      }

      if (dstConnId == it->connId) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "Peer issued RETIRE_CONNECTION_ID_FRAME refers to dst conn id field of containing packet."));
      }

      if (conn.nodeType == QuicNodeType::Server) {
        // in the server case, we need to queue unbinding from map
        CHECK(conn.connIdsRetiringSoon.has_value());
        conn.connIdsRetiringSoon->push_back(it->connId);
      }
      selfConnIds.erase(it);
      return true;
    }
    case QuicSimpleFrame::Type::HandshakeDoneFrame: {
      if (conn.nodeType == QuicNodeType::Server) {
        return quic::make_unexpected(QuicError(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "Received HANDSHAKE_DONE from client."));
      }
      // Mark the handshake confirmed in the handshake layer before doing
      // any dropping, as this gives us a chance to process ACKs in this
      // packet.
      conn.handshakeLayer->handshakeConfirmed();
      return true;
    }
    case QuicSimpleFrame::Type::KnobFrame: {
      const KnobFrame& knobFrame = *frame.asKnobFrame();
      conn.pendingEvents.knobs.emplace_back(
          knobFrame.knobSpace, knobFrame.id, knobFrame.blob->clone());
      return true;
    }
    case QuicSimpleFrame::Type::AckFrequencyFrame: {
      if (!conn.transportSettings.minAckDelay.has_value()) {
        // We do not accept ACK_FREQUENCY frames. This is a protocol
        // violation.
        return quic::make_unexpected(QuicError(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "Received ACK_FREQUENCY frame without announcing min_ack_delay"));
      }
      const auto ackFrequencyFrame = frame.asAckFrequencyFrame();
      auto& ackState = conn.ackStates.appDataAckState;
      if (!ackState.ackFrequencySequenceNumber ||
          ackFrequencyFrame->sequenceNumber >
              ackState.ackFrequencySequenceNumber.value()) {
        ackState.ackFrequencySequenceNumber = ackFrequencyFrame->sequenceNumber;
        ackState.tolerance = ackFrequencyFrame->packetTolerance;
        conn.ackStates.maxAckDelay = std::chrono::microseconds(
            std::max<uint64_t>(
                conn.transportSettings.minAckDelay->count(),
                ackFrequencyFrame->updateMaxAckDelay));
        ackState.reorderThreshold = ackFrequencyFrame->reorderThreshold;
      }
      return true;
    }
    case QuicSimpleFrame::Type::NewTokenFrame: {
      // TODO: client impl
      return true;
    }
  }
  return quic::make_unexpected(
      QuicError(TransportErrorCode::INTERNAL_ERROR, "Unknown frame type"));
}

} // namespace quic
