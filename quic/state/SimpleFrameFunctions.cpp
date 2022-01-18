/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicConstants.h>
#include <quic/state/QuicStateFunctions.h>
#include <quic/state/QuicStreamFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/stream/StreamSendHandlers.h>

namespace quic {
void sendSimpleFrame(QuicConnectionStateBase& conn, QuicSimpleFrame frame) {
  conn.pendingEvents.frames.emplace_back(std::move(frame));
}

folly::Optional<QuicSimpleFrame> updateSimpleFrameOnPacketClone(
    QuicConnectionStateBase& conn,
    const QuicSimpleFrame& frame) {
  switch (frame.type()) {
    case QuicSimpleFrame::Type::StopSendingFrame:
      if (!conn.streamManager->streamExists(
              frame.asStopSendingFrame()->streamId)) {
        return folly::none;
      }
      return QuicSimpleFrame(frame);
    case QuicSimpleFrame::Type::PathChallengeFrame:
      // Path validation timer expired, path validation failed;
      // or a different path validation was scheduled
      if (!conn.outstandingPathValidation ||
          *frame.asPathChallengeFrame() != *conn.outstandingPathValidation) {
        return folly::none;
      }
      return QuicSimpleFrame(frame);
    case QuicSimpleFrame::Type::PathResponseFrame:
      // Do not clone PATH_RESPONSE to avoid buffering
      return folly::none;
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
    const QuicSimpleFrame& simpleFrame) {
  switch (simpleFrame.type()) {
    case QuicSimpleFrame::Type::PathChallengeFrame:
      conn.outstandingPathValidation =
          std::move(conn.pendingEvents.pathChallenge);
      conn.pendingEvents.schedulePathValidationTimeout = true;
      // Start the clock to measure Rtt
      conn.pathChallengeStartTime = Clock::now();
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
    case QuicSimpleFrame::Type::StopSendingFrame: {
      const StopSendingFrame& stopSendingFrame = *frame.asStopSendingFrame();
      if (conn.streamManager->streamExists(stopSendingFrame.streamId)) {
        conn.pendingEvents.frames.push_back(stopSendingFrame);
      }
      break;
    }
    case QuicSimpleFrame::Type::PathChallengeFrame: {
      const PathChallengeFrame& pathChallenge = *frame.asPathChallengeFrame();
      if (conn.outstandingPathValidation &&
          pathChallenge == *conn.outstandingPathValidation) {
        conn.pendingEvents.pathChallenge = pathChallenge;
      }
      break;
    }
    case QuicSimpleFrame::Type::PathResponseFrame: {
      // Do not retransmit PATH_RESPONSE to avoid buffering
      break;
    }
    case QuicSimpleFrame::Type::HandshakeDoneFrame: {
      const auto& handshakeDoneFrame = *frame.asHandshakeDoneFrame();
      conn.pendingEvents.frames.push_back(handshakeDoneFrame);
      break;
    }
    case QuicSimpleFrame::Type::NewConnectionIdFrame:
    case QuicSimpleFrame::Type::MaxStreamsFrame:
    case QuicSimpleFrame::Type::RetireConnectionIdFrame:
    case QuicSimpleFrame::Type::KnobFrame:
    case QuicSimpleFrame::Type::AckFrequencyFrame:
    case QuicSimpleFrame::Type::NewTokenFrame:
      conn.pendingEvents.frames.push_back(frame);
      break;
  }
}

bool updateSimpleFrameOnPacketReceived(
    QuicConnectionStateBase& conn,
    const QuicSimpleFrame& frame,
    PacketNum /*packetNum*/,
    bool fromChangedPeerAddress) {
  switch (frame.type()) {
    case QuicSimpleFrame::Type::StopSendingFrame: {
      const StopSendingFrame& stopSending = *frame.asStopSendingFrame();
      auto stream = conn.streamManager->getStream(stopSending.streamId);
      if (stream) {
        sendStopSendingSMHandler(*stream, stopSending);
      }
      return true;
    }
    case QuicSimpleFrame::Type::PathChallengeFrame: {
      bool rotatedId = conn.retireAndSwitchPeerConnectionIds();
      if (!rotatedId) {
        throw QuicTransportException(
            "No more connection ids to use for new path.",
            TransportErrorCode::INVALID_MIGRATION);
      }
      const PathChallengeFrame& pathChallenge = *frame.asPathChallengeFrame();

      conn.pendingEvents.frames.emplace_back(
          PathResponseFrame(pathChallenge.pathData));
      return false;
    }
    case QuicSimpleFrame::Type::PathResponseFrame: {
      const PathResponseFrame& pathResponse = *frame.asPathResponseFrame();
      // Ignore the response if outstandingPathValidation is none or
      // the path data doesn't match what's in outstandingPathValidation
      if (fromChangedPeerAddress || !conn.outstandingPathValidation ||
          pathResponse.pathData != conn.outstandingPathValidation->pathData) {
        return false;
      }
      if (conn.qLogger) {
        conn.qLogger->addPathValidationEvent(true);
      }
      // TODO update source token,
      conn.outstandingPathValidation = folly::none;
      conn.pendingEvents.schedulePathValidationTimeout = false;

      // stop the clock to measure init rtt
      std::chrono::microseconds sampleRtt =
          std::chrono::duration_cast<std::chrono::microseconds>(
              Clock::now() - conn.pathChallengeStartTime);
      updateRtt(conn, sampleRtt, 0us);

      return false;
    }
    case QuicSimpleFrame::Type::NewConnectionIdFrame: {
      const NewConnectionIdFrame& newConnectionId =
          *frame.asNewConnectionIdFrame();

      // TODO vchynaro Ensure we ignore smaller subsequent retirePriorTos
      // than the largest seen so far.
      if (newConnectionId.retirePriorTo > newConnectionId.sequenceNumber) {
        throw QuicTransportException(
            "Retire prior to greater than sequence number",
            TransportErrorCode::PROTOCOL_VIOLATION);
      }

      for (const auto& existingPeerConnIdData : conn.peerConnectionIds) {
        if (existingPeerConnIdData.connId == newConnectionId.connectionId) {
          if (existingPeerConnIdData.sequenceNumber !=
              newConnectionId.sequenceNumber) {
            throw QuicTransportException(
                "Repeated connection id with different sequence number.",
                TransportErrorCode::PROTOCOL_VIOLATION);
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
        throw QuicTransportException(
            "Endpoint is already using 0-len connection ids.",
            TransportErrorCode::PROTOCOL_VIOLATION);
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
        conn.streamManager->setMaxLocalBidirectionalStreams(
            maxStreamsFrame.maxStreams);
      } else {
        conn.streamManager->setMaxLocalUnidirectionalStreams(
            maxStreamsFrame.maxStreams);
      }
      return true;
    }
    case QuicSimpleFrame::Type::RetireConnectionIdFrame: {
      return true;
    }
    case QuicSimpleFrame::Type::HandshakeDoneFrame: {
      if (conn.nodeType == QuicNodeType::Server) {
        throw QuicTransportException(
            "Received HANDSHAKE_DONE from client.",
            TransportErrorCode::PROTOCOL_VIOLATION,
            FrameType::HANDSHAKE_DONE);
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
      if (!conn.transportSettings.minAckDelay.hasValue()) {
        return true;
      }
      const auto ackFrequencyFrame = frame.asAckFrequencyFrame();
      auto& ackState = conn.ackStates.appDataAckState;
      if (!ackState.ackFrequencySequenceNumber ||
          ackFrequencyFrame->sequenceNumber >
              ackState.ackFrequencySequenceNumber.value()) {
        ackState.tolerance = ackFrequencyFrame->packetTolerance;
        ackState.ignoreReorder = ackFrequencyFrame->ignoreOrder;
        conn.ackStates.maxAckDelay =
            std::chrono::microseconds(std::max<uint64_t>(
                conn.transportSettings.minAckDelay->count(),
                ackFrequencyFrame->updateMaxAckDelay));
      }
      return true;
    }
    case QuicSimpleFrame::Type::NewTokenFrame: {
      // TODO: client impl
      return true;
    }
  }
  folly::assume_unreachable();
}

} // namespace quic
