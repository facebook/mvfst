/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/client/QuicClientTransport.h>

#include <folly/portability/Sockets.h>

#include <quic/QuicConstants.h>
#include <quic/api/LoopDetectorCallback.h>
#include <quic/api/QuicTransportFunctions.h>
#include <quic/client/handshake/ClientHandshakeFactory.h>
#include <quic/client/handshake/ClientTransportParametersExtension.h>
#include <quic/client/state/ClientStateMachine.h>
#include <quic/flowcontrol/QuicFlowController.h>
#include <quic/handshake/CryptoFactory.h>
#include <quic/happyeyeballs/QuicHappyEyeballsFunctions.h>
#include <quic/logging/QLoggerConstants.h>
#include <quic/loss/QuicLossFunctions.h>
#include <quic/state/AckHandlers.h>
#include <quic/state/QuicPacingFunctions.h>
#include <quic/state/SimpleFrameFunctions.h>
#include <quic/state/stream/StreamReceiveHandlers.h>
#include <quic/state/stream/StreamSendHandlers.h>

namespace fsp = folly::portability::sockets;

namespace quic {

using PacketDropReason = QuicTransportStatsCallback::PacketDropReason;

QuicClientTransport::QuicClientTransport(
    folly::EventBase* evb,
    std::unique_ptr<folly::AsyncUDPSocket> socket,
    std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
    size_t connectionIdSize)
    : QuicTransportBase(evb, std::move(socket)),
      happyEyeballsConnAttemptDelayTimeout_(this) {
  DCHECK(handshakeFactory);
  auto tempConn =
      std::make_unique<QuicClientConnectionState>(std::move(handshakeFactory));
  clientConn_ = tempConn.get();
  conn_.reset(tempConn.release());

  auto srcConnId = connectionIdSize > 0
      ? ConnectionId::createRandom(connectionIdSize)
      : ConnectionId(std::vector<uint8_t>());
  conn_->clientConnectionId = srcConnId;
  conn_->readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Client);
  conn_->readCodec->setClientConnectionId(srcConnId);
  conn_->selfConnectionIds.emplace_back(srcConnId, kInitialSequenceNumber);
  clientConn_->initialDestinationConnectionId =
      ConnectionId::createRandom(kMinInitialDestinationConnIdLength);
  clientConn_->originalDestinationConnectionId =
      clientConn_->initialDestinationConnectionId;
  conn_->clientChosenDestConnectionId =
      clientConn_->initialDestinationConnectionId;
  VLOG(4) << "initial dcid: "
          << clientConn_->initialDestinationConnectionId->hex();
  if (conn_->qLogger) {
    conn_->qLogger->setDcid(conn_->clientChosenDestConnectionId);
  }

  conn_->readCodec->setCodecParameters(CodecParameters(
      conn_->peerAckDelayExponent, conn_->originalVersion.value()));
  // TODO: generate this once we can generate the packet sequence number
  // correctly.
  // conn_->nextSequenceNum = folly::Random::secureRandom<PacketNum>();

  VLOG(10) << "client created " << *conn_;
}

QuicClientTransport::~QuicClientTransport() {
  VLOG(10) << "Destroyed connection to server=" << conn_->peerAddress;
  // The caller probably doesn't need the conn callback after destroying the
  // transport.
  connCallback_ = nullptr;
  // Close without draining.
  closeImpl(
      std::make_pair(
          QuicErrorCode(LocalErrorCode::SHUTTING_DOWN),
          std::string("Closing from client destructor")),
      false);

  if (conn_->happyEyeballsState.secondSocket) {
    auto sock = std::move(conn_->happyEyeballsState.secondSocket);
    sock->pauseRead();
    sock->close();
  }
}

void QuicClientTransport::processUDPData(
    const folly::SocketAddress& peer,
    NetworkDataSingle&& networkData) {
  BufQueue udpData;
  udpData.append(std::move(networkData.data));

  if (!conn_->version) {
    // We only check for version negotiation packets before the version
    // is negotiated.
    auto versionNegotiation =
        conn_->readCodec->tryParsingVersionNegotiation(udpData);
    if (versionNegotiation) {
      VLOG(4) << "Got version negotiation packet from peer=" << peer
              << " versions=" << std::hex << versionNegotiation->versions << " "
              << *this;

      throw QuicInternalException(
          "Received version negotiation packet",
          LocalErrorCode::CONNECTION_ABANDONED);
    }
  }

  for (uint16_t processedPackets = 0;
       !udpData.empty() && processedPackets < kMaxNumCoalescedPackets;
       processedPackets++) {
    processPacketData(peer, networkData.receiveTimePoint, udpData);
  }
  VLOG_IF(4, !udpData.empty())
      << "Leaving " << udpData.chainLength()
      << " bytes unprocessed after attempting to process "
      << kMaxNumCoalescedPackets << " packets.";
}

void QuicClientTransport::processPacketData(
    const folly::SocketAddress& peer,
    TimePoint receiveTimePoint,
    BufQueue& packetQueue) {
  auto packetSize = packetQueue.chainLength();
  if (packetSize == 0) {
    return;
  }
  auto parsedPacket = conn_->readCodec->parsePacket(
      packetQueue, conn_->ackStates, conn_->clientConnectionId->size());
  StatelessReset* statelessReset = parsedPacket.statelessReset();
  if (statelessReset) {
    const auto& token = clientConn_->statelessResetToken;
    if (statelessReset->token == token) {
      VLOG(4) << "Received Stateless Reset " << *this;
      conn_->peerConnectionError = std::make_pair(
          QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
          toString(LocalErrorCode::CONNECTION_RESET).str());
      throw QuicInternalException("Peer reset", LocalErrorCode::NO_ERROR);
    }
    VLOG(4) << "Drop StatelessReset for bad connId or token " << *this;
  }

  RetryPacket* retryPacket = parsedPacket.retryPacket();
  if (retryPacket) {
    if (conn_->qLogger) {
      conn_->qLogger->addPacket(*retryPacket, packetSize, true);
    }

    if (!clientConn_->retryToken.empty()) {
      VLOG(4) << "Server sent more than one retry packet";
      return;
    }

    const ConnectionId* originalDstConnId =
        &(*clientConn_->originalDestinationConnectionId);

    if (!clientConn_->clientHandshakeLayer->verifyRetryIntegrityTag(
            *originalDstConnId, *retryPacket)) {
      VLOG(4) << "The integrity tag in the retry packet was invalid. "
              << "Dropping bad retry packet.";
      return;
    }

    // Set the destination connection ID to be the value from the source
    // connection id of the retry packet
    clientConn_->initialDestinationConnectionId =
        retryPacket->header.getSourceConnId();

    auto released = static_cast<QuicClientConnectionState*>(conn_.release());
    std::unique_ptr<QuicClientConnectionState> uniqueClient(released);
    auto tempConn = undoAllClientStateForRetry(std::move(uniqueClient));

    clientConn_ = tempConn.get();
    conn_.reset(tempConn.release());

    clientConn_->retryToken = retryPacket->header.getToken();

    // TODO (amsharma): add a "RetryPacket" QLog event, and log it here.
    // TODO (amsharma): verify the "original_connection_id" parameter
    // upon receiving a subsequent initial from the server.

    startCryptoHandshake();
    return;
  }

  RegularQuicPacket* regularOptional = parsedPacket.regularPacket();
  if (!regularOptional) {
    QUIC_STATS(statsCallback_, onPacketDropped, PacketDropReason::PARSE_ERROR);
    if (conn_->qLogger) {
      conn_->qLogger->addPacketDrop(packetSize, kParse);
    }
    QUIC_TRACE(packet_drop, *conn_, "parse");
    return;
  }
  if (happyEyeballsEnabled_) {
    happyEyeballsOnDataReceived(
        *conn_, happyEyeballsConnAttemptDelayTimeout_, socket_, peer);
  }

  LongHeader* longHeader = regularOptional->header.asLong();
  ShortHeader* shortHeader = regularOptional->header.asShort();

  auto protectionLevel = regularOptional->header.getProtectionType();
  auto encryptionLevel = protectionTypeToEncryptionLevel(protectionLevel);

  auto packetNum = regularOptional->header.getPacketSequenceNum();
  auto pnSpace = regularOptional->header.getPacketNumberSpace();

  bool isProtectedPacket = protectionLevel == ProtectionType::KeyPhaseZero ||
      protectionLevel == ProtectionType::KeyPhaseOne;

  auto& regularPacket = *regularOptional;
  if (conn_->qLogger) {
    conn_->qLogger->addPacket(regularPacket, packetSize);
  }
  if (!isProtectedPacket) {
    for (auto& quicFrame : regularPacket.frames) {
      auto isPadding = quicFrame.asPaddingFrame();
      auto isAck = quicFrame.asReadAckFrame();
      auto isClose = quicFrame.asConnectionCloseFrame();
      auto isCrypto = quicFrame.asReadCryptoFrame();
      auto isPing = quicFrame.asPingFrame();
      // TODO: add path challenge and response
      if (!isPadding && !isAck && !isClose && !isCrypto && !isPing) {
        throw QuicTransportException(
            "Invalid frame", TransportErrorCode::PROTOCOL_VIOLATION);
      }
    }
  }

  // We got a packet that was not the version negotiation packet, that means
  // that the version is now bound to the new packet.
  // TODO: move this into the state machine.
  // TODO: get this from the crypto layer instead. This would be a security vuln
  // if we don't.
  if (!conn_->version) {
    conn_->version = conn_->originalVersion;
  }

  if (!conn_->serverConnectionId && longHeader) {
    conn_->serverConnectionId = longHeader->getSourceConnId();
    conn_->peerConnectionIds.emplace_back(
        longHeader->getSourceConnId(), kInitialSequenceNumber);
    conn_->readCodec->setServerConnectionId(*conn_->serverConnectionId);
  }

  // Error out if the connection id on the packet is not the one that is
  // expected.
  bool connidMatched = true;
  if (longHeader &&
      longHeader->getDestinationConnId() != *conn_->clientConnectionId) {
    connidMatched = false;
  } else if (
      shortHeader &&
      shortHeader->getConnectionId() != *conn_->clientConnectionId) {
    connidMatched = false;
  }
  if (!connidMatched) {
    throw QuicTransportException(
        "Invalid connection id", TransportErrorCode::PROTOCOL_VIOLATION);
  }
  auto& ackState = getAckState(*conn_, pnSpace);
  bool outOfOrder =
      updateLargestReceivedPacketNum(ackState, packetNum, receiveTimePoint);
  if (outOfOrder) {
    QUIC_STATS(conn_->statsCallback, onOutOfOrderPacketReceived);
  }

  bool pktHasRetransmittableData = false;
  bool pktHasCryptoData = false;

  for (auto& quicFrame : regularPacket.frames) {
    switch (quicFrame.type()) {
      case QuicFrame::Type::ReadAckFrame_E: {
        VLOG(10) << "Client received ack frame in packet=" << packetNum << " "
                 << *this;
        ReadAckFrame& ackFrame = *quicFrame.asReadAckFrame();
        processAckFrame(
            *conn_,
            pnSpace,
            ackFrame,
            [&](const OutstandingPacket& outstandingPacket,
                const QuicWriteFrame& packetFrame,
                const ReadAckFrame&) {
              auto outstandingProtectionType =
                  outstandingPacket.packet.header.getProtectionType();
              if (outstandingProtectionType == ProtectionType::KeyPhaseZero) {
                // If we received an ack for data that we sent in 1-rtt from
                // the server, we can assume that the server had successfully
                // derived the 1-rtt keys and hence received the client
                // finished message. We can mark the handshake as confirmed and
                // drop the handshake cipher and outstanding packets after the
                // processing loop.
                if (conn_->handshakeWriteCipher) {
                  conn_->handshakeLayer->handshakeConfirmed();
                }
                // TODO reap
                if (*conn_->version == QuicVersion::MVFST_D24) {
                  cancelHandshakeCryptoStreamRetransmissions(
                      *conn_->cryptoState);
                }
              }
              switch (packetFrame.type()) {
                case QuicWriteFrame::Type::WriteAckFrame_E: {
                  const WriteAckFrame& frame = *packetFrame.asWriteAckFrame();
                  DCHECK(!frame.ackBlocks.empty());
                  VLOG(4) << "Client received ack for largestAcked="
                          << frame.ackBlocks.front().end << " " << *this;
                  commonAckVisitorForAckFrame(ackState, frame);
                  break;
                }
                case QuicWriteFrame::Type::RstStreamFrame_E: {
                  const RstStreamFrame& frame = *packetFrame.asRstStreamFrame();
                  VLOG(4) << "Client received ack for reset frame stream="
                          << frame.streamId << " " << *this;

                  auto stream = conn_->streamManager->getStream(frame.streamId);
                  if (stream) {
                    sendRstAckSMHandler(*stream);
                  }
                  break;
                }
                case QuicWriteFrame::Type::WriteStreamFrame_E: {
                  const WriteStreamFrame& frame =
                      *packetFrame.asWriteStreamFrame();

                  auto ackedStream =
                      conn_->streamManager->getStream(frame.streamId);
                  VLOG(4) << "Client got ack for stream=" << frame.streamId
                          << " offset=" << frame.offset << " fin=" << frame.fin
                          << " data=" << frame.len
                          << " closed=" << (ackedStream == nullptr) << " "
                          << *this;
                  if (ackedStream) {
                    sendAckSMHandler(*ackedStream, frame);
                  }
                  break;
                }
                case QuicWriteFrame::Type::WriteCryptoFrame_E: {
                  const WriteCryptoFrame& frame =
                      *packetFrame.asWriteCryptoFrame();
                  auto cryptoStream = getCryptoStream(
                      *conn_->cryptoState,
                      protectionTypeToEncryptionLevel(
                          outstandingProtectionType));
                  processCryptoStreamAck(
                      *cryptoStream, frame.offset, frame.len);
                  break;
                }
                case QuicWriteFrame::Type::PingFrame_E:
                  conn_->pendingEvents.cancelPingTimeout = true;
                  break;
                case QuicWriteFrame::Type::QuicSimpleFrame_E:
                default:
                  // ignore other frames.
                  break;
              }
            },
            markPacketLoss,
            receiveTimePoint);
        break;
      }
      case QuicFrame::Type::RstStreamFrame_E: {
        RstStreamFrame& frame = *quicFrame.asRstStreamFrame();
        VLOG(10) << "Client received reset stream=" << frame.streamId << " "
                 << *this;
        pktHasRetransmittableData = true;
        auto streamId = frame.streamId;
        auto stream = conn_->streamManager->getStream(streamId);
        if (!stream) {
          break;
        }
        receiveRstStreamSMHandler(*stream, std::move(frame));
        break;
      }
      case QuicFrame::Type::ReadCryptoFrame_E: {
        pktHasRetransmittableData = true;
        pktHasCryptoData = true;
        ReadCryptoFrame& cryptoFrame = *quicFrame.asReadCryptoFrame();
        VLOG(10) << "Client received crypto data offset=" << cryptoFrame.offset
                 << " len=" << cryptoFrame.data->computeChainDataLength()
                 << " packetNum=" << packetNum << " " << *this;
        appendDataToReadBuffer(
            *getCryptoStream(*conn_->cryptoState, encryptionLevel),
            StreamBuffer(
                std::move(cryptoFrame.data), cryptoFrame.offset, false));
        break;
      }
      case QuicFrame::Type::ReadStreamFrame_E: {
        ReadStreamFrame& frame = *quicFrame.asReadStreamFrame();
        VLOG(10) << "Client received stream data for stream=" << frame.streamId
                 << " offset=" << frame.offset
                 << " len=" << frame.data->computeChainDataLength()
                 << " fin=" << frame.fin << " packetNum=" << packetNum << " "
                 << *this;
        auto stream = conn_->streamManager->getStream(frame.streamId);
        pktHasRetransmittableData = true;
        if (!stream) {
          VLOG(10) << "Could not find stream=" << frame.streamId << " "
                   << *conn_;
          break;
        }
        receiveReadStreamFrameSMHandler(*stream, std::move(frame));
        break;
      }
      case QuicFrame::Type::MaxDataFrame_E: {
        MaxDataFrame& connWindowUpdate = *quicFrame.asMaxDataFrame();
        VLOG(10) << "Client received max data offset="
                 << connWindowUpdate.maximumData << " " << *this;
        pktHasRetransmittableData = true;
        handleConnWindowUpdate(*conn_, connWindowUpdate, packetNum);
        break;
      }
      case QuicFrame::Type::MaxStreamDataFrame_E: {
        MaxStreamDataFrame& streamWindowUpdate =
            *quicFrame.asMaxStreamDataFrame();
        VLOG(10) << "Client received max stream data stream="
                 << streamWindowUpdate.streamId
                 << " offset=" << streamWindowUpdate.maximumData << " "
                 << *this;
        if (isReceivingStream(conn_->nodeType, streamWindowUpdate.streamId)) {
          throw QuicTransportException(
              "Received MaxStreamDataFrame for receiving stream.",
              TransportErrorCode::STREAM_STATE_ERROR);
        }
        pktHasRetransmittableData = true;
        auto stream =
            conn_->streamManager->getStream(streamWindowUpdate.streamId);
        if (stream) {
          handleStreamWindowUpdate(
              *stream, streamWindowUpdate.maximumData, packetNum);
        }
        break;
      }
      case QuicFrame::Type::DataBlockedFrame_E: {
        VLOG(10) << "Client received blocked " << *this;
        pktHasRetransmittableData = true;
        handleConnBlocked(*conn_);
        break;
      }
      case QuicFrame::Type::StreamDataBlockedFrame_E: {
        // peer wishes to send data, but is unable to due to stream-level flow
        // control
        StreamDataBlockedFrame& blocked = *quicFrame.asStreamDataBlockedFrame();
        VLOG(10) << "Client received blocked stream=" << blocked.streamId << " "
                 << *this;
        pktHasRetransmittableData = true;
        auto stream = conn_->streamManager->getStream(blocked.streamId);
        if (stream) {
          handleStreamBlocked(*stream);
        }
        break;
      }
      case QuicFrame::Type::StreamsBlockedFrame_E: {
        // peer wishes to open a stream, but is unable to due to the maximum
        // stream limit set by us
        StreamsBlockedFrame& blocked = *quicFrame.asStreamsBlockedFrame();
        VLOG(10) << "Client received stream blocked limit="
                 << blocked.streamLimit << " " << *this;
        // TODO implement handler for it
        break;
      }
      case QuicFrame::Type::ConnectionCloseFrame_E: {
        ConnectionCloseFrame& connFrame = *quicFrame.asConnectionCloseFrame();
        auto errMsg = folly::to<std::string>(
            "Client closed by peer reason=", connFrame.reasonPhrase);
        VLOG(4) << errMsg << " " << *this;
        // we want to deliver app callbacks with the peer supplied error,
        // but send a NO_ERROR to the peer.
        if (conn_->qLogger) {
          conn_->qLogger->addTransportStateUpdate(getPeerClose(errMsg));
        }
        QUIC_TRACE(recvd_close, *conn_, errMsg.c_str());
        conn_->peerConnectionError = std::make_pair(
            QuicErrorCode(connFrame.errorCode), std::move(errMsg));
        throw QuicTransportException(
            "Peer closed", TransportErrorCode::NO_ERROR);
        break;
      }
      case QuicFrame::Type::PingFrame_E:
        // Ping isn't retransmittable. But we would like to ack them early.
        pktHasRetransmittableData = true;
        break;
      case QuicFrame::Type::PaddingFrame_E:
        break;
      case QuicFrame::Type::QuicSimpleFrame_E: {
        QuicSimpleFrame& simpleFrame = *quicFrame.asQuicSimpleFrame();
        pktHasRetransmittableData = true;
        updateSimpleFrameOnPacketReceived(
            *conn_, simpleFrame, packetNum, false);
        break;
      }
      default:
        break;
    }
  }

  auto handshakeLayer = clientConn_->clientHandshakeLayer;
  if (handshakeLayer->getPhase() == ClientHandshake::Phase::Established &&
      *conn_->version != QuicVersion::MVFST_D24) {
    handshakeConfirmed(*conn_);
  }

  // Try reading bytes off of crypto, and performing a handshake.
  auto cryptoData = readDataFromCryptoStream(
      *getCryptoStream(*conn_->cryptoState, encryptionLevel));
  if (cryptoData) {
    bool hadOneRttKey = conn_->oneRttWriteCipher != nullptr;
    handshakeLayer->doHandshake(std::move(cryptoData), encryptionLevel);
    bool oneRttKeyDerivationTriggered = false;
    if (!hadOneRttKey && conn_->oneRttWriteCipher) {
      oneRttKeyDerivationTriggered = true;
      updatePacingOnKeyEstablished(*conn_);
    }
    if (conn_->oneRttWriteCipher && conn_->readCodec->getOneRttReadCipher() &&
        conn_->version != QuicVersion::MVFST_D24) {
      conn_->zeroRttWriteCipher.reset();
      conn_->zeroRttWriteHeaderCipher.reset();
    }
    auto zeroRttRejected = handshakeLayer->getZeroRttRejected();
    if (zeroRttRejected.has_value() && *zeroRttRejected) {
      if (conn_->qLogger) {
        conn_->qLogger->addTransportStateUpdate(kZeroRttRejected);
      }
      QUIC_TRACE(zero_rtt, *conn_, "rejected");
      handshakeLayer->removePsk(hostname_);
    } else if (zeroRttRejected.has_value()) {
      if (conn_->qLogger) {
        conn_->qLogger->addTransportStateUpdate(kZeroRttAccepted);
      }
      QUIC_TRACE(zero_rtt, *conn_, "accepted");
    }
    // We should get transport parameters if we've derived 1-rtt keys and 0-rtt
    // was rejected, or we have derived 1-rtt keys and 0-rtt was never
    // attempted.
    if (oneRttKeyDerivationTriggered) {
      auto serverParams = handshakeLayer->getServerTransportParams();
      if (!serverParams) {
        throw QuicTransportException(
            "No server transport params",
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
      }
      if ((zeroRttRejected.has_value() && *zeroRttRejected) ||
          !zeroRttRejected.has_value()) {
        auto originalPeerMaxOffset =
            conn_->flowControlState.peerAdvertisedMaxOffset;
        auto originalPeerInitialStreamOffsetBidiLocal =
            conn_->flowControlState
                .peerAdvertisedInitialMaxStreamOffsetBidiLocal;
        auto originalPeerInitialStreamOffsetBidiRemote =
            conn_->flowControlState
                .peerAdvertisedInitialMaxStreamOffsetBidiRemote;
        auto originalPeerInitialStreamOffsetUni =
            conn_->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni;
        VLOG(10) << "Client negotiated transport params " << *this;
        auto maxStreamsBidi = getIntegerParameter(
            TransportParameterId::initial_max_streams_bidi,
            serverParams->parameters);
        auto maxStreamsUni = getIntegerParameter(
            TransportParameterId::initial_max_streams_uni,
            serverParams->parameters);
        processServerInitialParams(
            *clientConn_, std::move(*serverParams), packetNum);

        cacheServerInitialParams(
            *clientConn_,
            conn_->flowControlState.peerAdvertisedMaxOffset,
            conn_->flowControlState
                .peerAdvertisedInitialMaxStreamOffsetBidiLocal,
            conn_->flowControlState
                .peerAdvertisedInitialMaxStreamOffsetBidiRemote,
            conn_->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni,
            maxStreamsBidi.value_or(0),
            maxStreamsUni.value_or(0));

        const auto& statelessResetToken = clientConn_->statelessResetToken;
        if (statelessResetToken) {
          conn_->readCodec->setStatelessResetToken(*statelessResetToken);
        }
        if (zeroRttRejected.has_value() && *zeroRttRejected) {
          // verify that the new flow control parameters are >= the original
          // transport parameters that were use. This is the easy case. If the
          // flow control decreases then we are just screwed and we need to have
          // the app retry the connection. The other parameters can be updated.
          // TODO: implement undo transport state on retry.
          if (originalPeerMaxOffset >
                  conn_->flowControlState.peerAdvertisedMaxOffset ||
              originalPeerInitialStreamOffsetBidiLocal >
                  conn_->flowControlState
                      .peerAdvertisedInitialMaxStreamOffsetBidiLocal ||
              originalPeerInitialStreamOffsetBidiRemote >
                  conn_->flowControlState
                      .peerAdvertisedInitialMaxStreamOffsetBidiRemote ||

              originalPeerInitialStreamOffsetUni >
                  conn_->flowControlState
                      .peerAdvertisedInitialMaxStreamOffsetUni) {
            throw QuicTransportException(
                "Rejection of zero rtt parameters unsupported",
                TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
          }
        }
      }
      // TODO This sucks, but manually update the max packet size until we fix
      // 0-rtt transport parameters.
      if (conn_->transportSettings.canIgnorePathMTU &&
          zeroRttRejected.has_value() && !*zeroRttRejected) {
        auto updatedPacketSize = getIntegerParameter(
            TransportParameterId::max_packet_size, serverParams->parameters);
        updatedPacketSize = std::max<uint64_t>(
            updatedPacketSize.value_or(kDefaultUDPSendPacketLen),
            kDefaultUDPSendPacketLen);
        updatedPacketSize =
            std::min<uint64_t>(*updatedPacketSize, kDefaultMaxUDPPayload);
        conn_->udpSendPacketLen = *updatedPacketSize;
      }
    }

    if (zeroRttRejected.has_value() && *zeroRttRejected) {
      // TODO: Make sure the alpn is the same, if not then do a full undo of the
      // state.
      clientConn_->zeroRttWriteCipher.reset();
      clientConn_->zeroRttWriteHeaderCipher.reset();
      markZeroRttPacketsLost(*conn_, markPacketLoss);
    }
  }
  // TODO this is incorrect and needs to be removed post MVFST_D24
  if (conn_->version == QuicVersion::MVFST_D24 &&
      (protectionLevel == ProtectionType::KeyPhaseZero ||
       protectionLevel == ProtectionType::KeyPhaseOne)) {
    DCHECK(conn_->oneRttWriteCipher);
    clientConn_->clientHandshakeLayer->handshakeConfirmed();
    conn_->readCodec->onHandshakeDone(receiveTimePoint);
  }
  updateAckSendStateOnRecvPacket(
      *conn_,
      ackState,
      outOfOrder,
      pktHasRetransmittableData,
      pktHasCryptoData);
  if (encryptionLevel == EncryptionLevel::Handshake &&
      conn_->version != QuicVersion::MVFST_D24 && conn_->initialWriteCipher) {
    conn_->initialWriteCipher.reset();
    conn_->initialHeaderCipher.reset();
    conn_->readCodec->setInitialReadCipher(nullptr);
    conn_->readCodec->setInitialHeaderCipher(nullptr);
    implicitAckCryptoStream(*conn_, EncryptionLevel::Initial);
  }
}

void QuicClientTransport::onReadData(
    const folly::SocketAddress& peer,
    NetworkDataSingle&& networkData) {
  if (closeState_ == CloseState::CLOSED) {
    // If we are closed, then we shoudn't process new network data.
    // TODO: we might want to process network data if we decide that we should
    // exit draining state early
    QUIC_STATS(
        statsCallback_, onPacketDropped, PacketDropReason::CLIENT_STATE_CLOSED);
    if (conn_->qLogger) {
      conn_->qLogger->addPacketDrop(0, kAlreadyClosed);
    }
    QUIC_TRACE(packet_drop, *conn_, "already_closed");
    return;
  }
  bool waitingForFirstPacket = !hasReceivedPackets(*conn_);
  processUDPData(peer, std::move(networkData));
  if (connCallback_ && waitingForFirstPacket && hasReceivedPackets(*conn_)) {
    connCallback_->onFirstPeerPacketProcessed();
  }
  if (!transportReadyNotified_ && hasWriteCipher()) {
    transportReadyNotified_ = true;
    CHECK_NOTNULL(connCallback_)->onTransportReady();
  }

  // Checking connCallback_ because application will start to write data
  // in onTransportReady, if the write fails, QuicSocket can be closed
  // and connCallback_ is set nullptr.
  if (connCallback_ && !replaySafeNotified_ && conn_->oneRttWriteCipher) {
    replaySafeNotified_ = true;
    // We don't need this any more. Also unset it so that we don't allow random
    // middleboxes to shutdown our connection once we have crypto keys.
    socket_->setErrMessageCallback(nullptr);
    connCallback_->onReplaySafe();
  }

  maybeSendTransportKnobs();
}

void QuicClientTransport::writeData() {
  // TODO: replace with write in state machine.
  // TODO: change to draining when we move the client to have a draining state
  // as well.
  QuicVersion version = conn_->version.value_or(*conn_->originalVersion);
  const ConnectionId& srcConnId = *conn_->clientConnectionId;
  const ConnectionId* destConnId =
      &(*clientConn_->initialDestinationConnectionId);
  if (conn_->serverConnectionId) {
    destConnId = &(*conn_->serverConnectionId);
  }
  if (closeState_ == CloseState::CLOSED) {
    auto rtt = clientConn_->lossState.srtt == 0us
        ? clientConn_->transportSettings.initialRtt
        : clientConn_->lossState.srtt;
    if (clientConn_->lastCloseSentTime &&
        Clock::now() - *clientConn_->lastCloseSentTime < rtt) {
      return;
    }
    clientConn_->lastCloseSentTime = Clock::now();
    if (clientConn_->clientHandshakeLayer->getPhase() ==
            ClientHandshake::Phase::Established &&
        conn_->oneRttWriteCipher) {
      CHECK(conn_->oneRttWriteHeaderCipher);
      writeShortClose(
          *socket_,
          *conn_,
          *destConnId,
          conn_->localConnectionError,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher);
    }
    if (conn_->handshakeWriteCipher &&
        *conn_->version != QuicVersion::MVFST_D24) {
      CHECK(conn_->handshakeWriteHeaderCipher);
      writeLongClose(
          *socket_,
          *conn_,
          srcConnId,
          *destConnId,
          LongHeader::Types::Handshake,
          conn_->localConnectionError,
          *conn_->handshakeWriteCipher,
          *conn_->handshakeWriteHeaderCipher,
          version);
    }
    if (conn_->initialWriteCipher) {
      CHECK(conn_->initialHeaderCipher);
      writeLongClose(
          *socket_,
          *conn_,
          srcConnId,
          *destConnId,
          LongHeader::Types::Initial,
          conn_->localConnectionError,
          *conn_->initialWriteCipher,
          *conn_->initialHeaderCipher,
          version);
    }
    return;
  }

  uint64_t packetLimit =
      (isConnectionPaced(*conn_)
           ? conn_->pacer->updateAndGetWriteBatchSize(Clock::now())
           : conn_->transportSettings.writeConnectionDataPacketsLimit);
  if (conn_->initialWriteCipher) {
    auto& initialCryptoStream =
        *getCryptoStream(*conn_->cryptoState, EncryptionLevel::Initial);
    CryptoStreamScheduler initialScheduler(*conn_, initialCryptoStream);

    if ((initialCryptoStream.retransmissionBuffer.size() &&
         conn_->outstandings.initialPacketsCount &&
         conn_->pendingEvents.numProbePackets) ||
        initialScheduler.hasData() ||
        (conn_->ackStates.initialAckState.needsToSendAckImmediately &&
         hasAcksToSchedule(conn_->ackStates.initialAckState))) {
      CHECK(conn_->initialHeaderCipher);
      packetLimit -= writeCryptoAndAckDataToSocket(
          *socket_,
          *conn_,
          srcConnId /* src */,
          *destConnId /* dst */,
          LongHeader::Types::Initial,
          *conn_->initialWriteCipher,
          *conn_->initialHeaderCipher,
          version,
          packetLimit,
          clientConn_->retryToken);
    }
    if (!packetLimit && !conn_->pendingEvents.numProbePackets) {
      return;
    }
  }
  if (conn_->handshakeWriteCipher) {
    auto& handshakeCryptoStream =
        *getCryptoStream(*conn_->cryptoState, EncryptionLevel::Handshake);
    CryptoStreamScheduler handshakeScheduler(*conn_, handshakeCryptoStream);
    if ((conn_->outstandings.handshakePacketsCount &&
         handshakeCryptoStream.retransmissionBuffer.size() &&
         conn_->pendingEvents.numProbePackets) ||
        handshakeScheduler.hasData() ||
        (conn_->ackStates.handshakeAckState.needsToSendAckImmediately &&
         hasAcksToSchedule(conn_->ackStates.handshakeAckState))) {
      CHECK(conn_->handshakeWriteHeaderCipher);
      packetLimit -= writeCryptoAndAckDataToSocket(
          *socket_,
          *conn_,
          srcConnId /* src */,
          *destConnId /* dst */,
          LongHeader::Types::Handshake,
          *conn_->handshakeWriteCipher,
          *conn_->handshakeWriteHeaderCipher,
          version,
          packetLimit);
    }
    if (!packetLimit && !conn_->pendingEvents.numProbePackets) {
      return;
    }
  }
  if (clientConn_->zeroRttWriteCipher && !conn_->oneRttWriteCipher) {
    CHECK(clientConn_->zeroRttWriteHeaderCipher);
    packetLimit -= writeZeroRttDataToSocket(
        *socket_,
        *conn_,
        srcConnId /* src */,
        *destConnId /* dst */,
        *clientConn_->zeroRttWriteCipher,
        *clientConn_->zeroRttWriteHeaderCipher,
        version,
        packetLimit);
  }
  if (!packetLimit && !conn_->pendingEvents.numProbePackets) {
    return;
  }
  if (conn_->oneRttWriteCipher) {
    CHECK(clientConn_->oneRttWriteHeaderCipher);
    writeQuicDataExceptCryptoStreamToSocket(
        *socket_,
        *conn_,
        srcConnId,
        *destConnId,
        *conn_->oneRttWriteCipher,
        *conn_->oneRttWriteHeaderCipher,
        version,
        packetLimit);
  }
}

void QuicClientTransport::startCryptoHandshake() {
  auto self = this->shared_from_this();
  // Set idle timer whenever crypto starts so that we can restart the idle timer
  // after a version negotiation as well.
  setIdleTimer();
  // TODO: no need to close the transport if there is an error in the
  // handshake.
  // We need to update the flow control settings every time we start a crypto
  // handshake. This is so that we can reset the flow control settings when
  // we go through version negotiation as well.
  updateFlowControlStateWithSettings(
      conn_->flowControlState, conn_->transportSettings);

  auto handshakeLayer = clientConn_->clientHandshakeLayer;
  auto& cryptoFactory = handshakeLayer->getCryptoFactory();

  auto version = conn_->originalVersion.value();
  conn_->initialWriteCipher = cryptoFactory.getClientInitialCipher(
      *clientConn_->initialDestinationConnectionId, version);
  conn_->readCodec->setInitialReadCipher(cryptoFactory.getServerInitialCipher(
      *clientConn_->initialDestinationConnectionId, version));
  conn_->readCodec->setInitialHeaderCipher(
      cryptoFactory.makeServerInitialHeaderCipher(
          *clientConn_->initialDestinationConnectionId, version));
  conn_->initialHeaderCipher = cryptoFactory.makeClientInitialHeaderCipher(
      *clientConn_->initialDestinationConnectionId, version);

  // Add partial reliability parameter to customTransportParameters_.
  setPartialReliabilityTransportParameter();
  setD6DBasePMTUTransportParameter();
  setD6DRaiseTimeoutTransportParameter();
  setD6DProbeTimeoutTransportParameter();

  auto paramsExtension = std::make_shared<ClientTransportParametersExtension>(
      conn_->originalVersion.value(),
      conn_->transportSettings.advertisedInitialConnectionWindowSize,
      conn_->transportSettings.advertisedInitialBidiLocalStreamWindowSize,
      conn_->transportSettings.advertisedInitialBidiRemoteStreamWindowSize,
      conn_->transportSettings.advertisedInitialUniStreamWindowSize,
      conn_->transportSettings.advertisedInitialMaxStreamsBidi,
      conn_->transportSettings.advertisedInitialMaxStreamsUni,
      conn_->transportSettings.idleTimeout,
      conn_->transportSettings.ackDelayExponent,
      conn_->transportSettings.maxRecvPacketSize,
      conn_->transportSettings.selfActiveConnectionIdLimit,
      conn_->clientConnectionId.value(),
      customTransportParameters_);
  conn_->transportParametersEncoded = true;
  handshakeLayer->connect(hostname_, std::move(paramsExtension));

  writeSocketData();
  if (!transportReadyNotified_ && clientConn_->zeroRttWriteCipher) {
    transportReadyNotified_ = true;
    runOnEvbAsync([](auto self) {
      auto clientPtr = static_cast<QuicClientTransport*>(self.get());
      if (clientPtr->connCallback_) {
        clientPtr->connCallback_->onTransportReady();
      }
    });
  }
}

bool QuicClientTransport::hasWriteCipher() const {
  return clientConn_->oneRttWriteCipher || clientConn_->zeroRttWriteCipher;
}

std::shared_ptr<QuicTransportBase> QuicClientTransport::sharedGuard() {
  return shared_from_this();
}

bool QuicClientTransport::isTLSResumed() const {
  return clientConn_->clientHandshakeLayer->isTLSResumed();
}

void QuicClientTransport::errMessage(
    FOLLY_MAYBE_UNUSED const cmsghdr& cmsg) noexcept {
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  if ((cmsg.cmsg_level == SOL_IP && cmsg.cmsg_type == IP_RECVERR) ||
      (cmsg.cmsg_level == SOL_IPV6 && cmsg.cmsg_type == IPV6_RECVERR)) {
    const struct sock_extended_err* serr =
        reinterpret_cast<const struct sock_extended_err*>(CMSG_DATA(&cmsg));
    auto connectionError = (serr->ee_errno == ECONNREFUSED) ||
        (serr->ee_errno == ENETUNREACH) || (serr->ee_errno == ENETDOWN);
    if (!connectionError) {
      return;
    }
    auto errStr = folly::errnoStr(serr->ee_errno);
    runOnEvbAsync([errString = std::move(errStr)](auto self) {
      auto quicError = std::make_pair(
          QuicErrorCode(LocalErrorCode::CONNECT_FAILED), errString);
      auto clientPtr = static_cast<QuicClientTransport*>(self.get());
      clientPtr->closeImpl(std::move(quicError), false, false);
    });
  }
#endif
}

void QuicClientTransport::onReadError(
    const folly::AsyncSocketException& ex) noexcept {
  if (closeState_ == CloseState::OPEN) {
    // closeNow will skip draining the socket. onReadError doesn't gets
    // triggered by retriable errors. If we are here, there is no point of
    // draining the socket.
    runOnEvbAsync([ex](auto self) {
      auto clientPtr = static_cast<QuicClientTransport*>(self.get());
      clientPtr->closeNow(std::make_pair(
          QuicErrorCode(LocalErrorCode::CONNECTION_ABANDONED),
          std::string(ex.what())));
    });
  }
}

void QuicClientTransport::getReadBuffer(void** buf, size_t* len) noexcept {
  DCHECK(conn_) << "trying to receive packets without a connection";
  auto readBufferSize =
      conn_->transportSettings.maxRecvPacketSize * numGROBuffers_;
  readBuffer_ = folly::IOBuf::create(readBufferSize);
  *buf = readBuffer_->writableData();
  *len = readBufferSize;
}

void QuicClientTransport::onDataAvailable(
    const folly::SocketAddress& server,
    size_t len,
    bool truncated,
    OnDataAvailableParams params) noexcept {
  VLOG(10) << "Got data from socket peer=" << server << " len=" << len;
  auto packetReceiveTime = Clock::now();
  Buf data = std::move(readBuffer_);

  if (params.gro <= 0) {
    if (truncated) {
      // This is an error, drop the packet.
      QUIC_STATS(
          statsCallback_, onPacketDropped, PacketDropReason::UDP_TRUNCATED);
      if (conn_->qLogger) {
        conn_->qLogger->addPacketDrop(len, kUdpTruncated);
      }
      QUIC_TRACE(packet_drop, *conn_, "udp_truncated");
      if (conn_->loopDetectorCallback) {
        conn_->readDebugState.noReadReason = NoReadReason::TRUNCATED;
        conn_->loopDetectorCallback->onSuspiciousReadLoops(
            ++conn_->readDebugState.loopCount,
            conn_->readDebugState.noReadReason);
      }
      return;
    }
    data->append(len);
    trackDatagramReceived(len);
    NetworkData networkData(std::move(data), packetReceiveTime);
    onNetworkData(server, std::move(networkData));
  } else {
    // if we receive a truncated packet
    // we still need to consider the prev valid ones
    // AsyncUDPSocket::handleRead() sets the len to be the
    // buffer size in case the data is truncated
    if (truncated) {
      auto delta = len % params.gro;
      len -= delta;

      QUIC_STATS(
          statsCallback_, onPacketDropped, PacketDropReason::UDP_TRUNCATED);
      if (conn_->qLogger) {
        conn_->qLogger->addPacketDrop(delta, kUdpTruncated);
      }
      QUIC_TRACE(packet_drop, *conn_, "udp_truncated");
    }

    data->append(len);
    trackDatagramReceived(len);

    NetworkData networkData;
    networkData.receiveTimePoint = packetReceiveTime;
    networkData.packets.reserve((len + params.gro - 1) / params.gro);
    size_t remaining = len;
    size_t offset = 0;
    while (remaining) {
      if (static_cast<int>(remaining) > params.gro) {
        auto tmp = data->cloneOne();
        // start at offset
        tmp->trimStart(offset);
        // the actual len is len - offset now
        // leave params.gro bytes
        tmp->trimEnd(len - offset - params.gro);
        DCHECK_EQ(tmp->length(), params.gro);

        offset += params.gro;
        remaining -= params.gro;
        networkData.packets.emplace_back(std::move(tmp));
      } else {
        // do not clone the last packet
        // start at offset, use all the remaining data
        data->trimStart(offset);
        DCHECK_EQ(data->length(), remaining);
        remaining = 0;
        networkData.packets.emplace_back(std::move(data));
      }
    }

    onNetworkData(server, std::move(networkData));
  }
}

bool QuicClientTransport::shouldOnlyNotify() {
  return conn_->transportSettings.shouldRecvBatch;
}

void QuicClientTransport::recvMsg(
    folly::AsyncUDPSocket& sock,
    uint64_t readBufferSize,
    int numPackets,
    NetworkData& networkData,
    folly::Optional<folly::SocketAddress>& server,
    size_t& totalData) {
  for (int packetNum = 0; packetNum < numPackets; ++packetNum) {
    // We create 1 buffer per packet so that it is not shared, this enables
    // us to decrypt in place. If the fizz decrypt api could decrypt in-place
    // even if shared, then we could allocate one giant IOBuf here.
    Buf readBuffer = folly::IOBuf::create(readBufferSize);
    struct iovec vec {};
    vec.iov_base = readBuffer->writableData();
    vec.iov_len = readBufferSize;

    sockaddr* rawAddr{nullptr};
    struct sockaddr_storage addrStorage {};
    socklen_t addrLen{sizeof(addrStorage)};
    if (!server) {
      rawAddr = reinterpret_cast<sockaddr*>(&addrStorage);
      rawAddr->sa_family = sock.address().getFamily();
    }

    int flags = 0;
    folly::AsyncUDPSocket::ReadCallback::OnDataAvailableParams params;
    struct msghdr msg {};
    msg.msg_name = rawAddr;
    msg.msg_namelen = size_t(addrLen);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    bool useGRO = sock.getGRO() > 0;
    bool useTS = sock.getTimestamping() > 0;
    char control[folly::AsyncUDPSocket::ReadCallback::OnDataAvailableParams::
                     kCmsgSpace] = {};

    if (useGRO || useTS) {
      msg.msg_control = control;
      msg.msg_controllen = sizeof(control);

      // we need to consider MSG_TRUNC too
      flags |= MSG_TRUNC;
    }
#endif

    ssize_t ret = sock.recvmsg(&msg, flags);
    if (ret < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // If we got a retriable error, let us continue.
        if (conn_->loopDetectorCallback) {
          conn_->readDebugState.noReadReason = NoReadReason::RETRIABLE_ERROR;
        }
        break;
      }
      // If we got a non-retriable error, we might have received
      // a packet that we could process, however let's just quit early.
      sock.pauseRead();
      if (conn_->loopDetectorCallback) {
        conn_->readDebugState.noReadReason = NoReadReason::NONRETRIABLE_ERROR;
      }
      return onReadError(folly::AsyncSocketException(
          folly::AsyncSocketException::INTERNAL_ERROR,
          "::recvmsg() failed",
          errno));
    } else if (ret == 0) {
      break;
    }
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (useGRO) {
      folly::AsyncUDPSocket::fromMsg(params, msg);

      // truncated
      if ((size_t)ret > readBufferSize) {
        ret = readBufferSize;
        if (params.gro > 0) {
          ret = ret - ret % params.gro;
        }
      }
    }
#endif
    size_t bytesRead = size_t(ret);
    totalData += bytesRead;
    if (!server) {
      server = folly::SocketAddress();
      server->setFromSockaddr(rawAddr, addrLen);
    }
    VLOG(10) << "Got data from socket peer=" << *server << " len=" << bytesRead;
    readBuffer->append(bytesRead);
    if (params.gro > 0) {
      size_t len = bytesRead;
      size_t remaining = len;
      size_t offset = 0;
      size_t totalNumPackets =
          networkData.packets.size() + ((len + params.gro - 1) / params.gro);
      networkData.packets.reserve(totalNumPackets);
      while (remaining) {
        if (static_cast<int>(remaining) > params.gro) {
          auto tmp = readBuffer->cloneOne();
          // start at offset
          tmp->trimStart(offset);
          // the actual len is len - offset now
          // leave gro bytes
          tmp->trimEnd(len - offset - params.gro);
          DCHECK_EQ(tmp->length(), params.gro);

          offset += params.gro;
          remaining -= params.gro;
          networkData.packets.emplace_back(std::move(tmp));
        } else {
          // do not clone the last packet
          // start at offset, use all the remaining data
          readBuffer->trimStart(offset);
          DCHECK_EQ(readBuffer->length(), remaining);
          remaining = 0;
          networkData.packets.emplace_back(std::move(readBuffer));
        }
      }
    } else {
      networkData.packets.emplace_back(std::move(readBuffer));
    }
    if (conn_->qLogger) {
      conn_->qLogger->addDatagramReceived(bytesRead);
    }
  }
}

void QuicClientTransport::recvMmsg(
    folly::AsyncUDPSocket& sock,
    uint64_t readBufferSize,
    int numPackets,
    NetworkData& networkData,
    folly::Optional<folly::SocketAddress>& server,
    size_t& totalData) {
  const size_t addrLen = sizeof(struct sockaddr_storage);

  auto& msgs = recvmmsgStorage_.msgs;
  auto& addrs = recvmmsgStorage_.addrs;
  auto& readBuffers = recvmmsgStorage_.readBuffers;
  auto& iovecs = recvmmsgStorage_.iovecs;
  auto& freeBufs = recvmmsgStorage_.freeBufs;
  int flags = 0;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
  bool useGRO = sock.getGRO() > 0;
  bool useTS = sock.getTimestamping() > 0;
  std::vector<std::array<
      char,
      folly::AsyncUDPSocket::ReadCallback::OnDataAvailableParams::kCmsgSpace>>
      controlVec(useGRO ? numPackets : 0);

  // we need to consider MSG_TRUNC too
  if (useGRO) {
    flags |= MSG_TRUNC;
  }
#endif

  for (int i = 0; i < numPackets; ++i) {
    Buf readBuffer;
    if (freeBufs.empty()) {
      readBuffer = folly::IOBuf::create(readBufferSize);
    } else {
      readBuffer = std::move(freeBufs.back());
      DCHECK(readBuffer != nullptr);
      freeBufs.pop_back();
    }
    iovecs[i].iov_base = readBuffer->writableData();
    iovecs[i].iov_len = readBufferSize;
    readBuffers[i] = std::move(readBuffer);

    auto* rawAddr = reinterpret_cast<sockaddr*>(&addrs[i]);
    rawAddr->sa_family = socket_->address().getFamily();

    struct msghdr* msg = &msgs[i].msg_hdr;
    msg->msg_name = rawAddr;
    msg->msg_namelen = addrLen;
    msg->msg_iov = &iovecs[i];
    msg->msg_iovlen = 1;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (useGRO || useTS) {
      ::memset(controlVec[i].data(), 0, controlVec[i].size());
      msg->msg_control = controlVec[i].data();
      msg->msg_controllen = controlVec[i].size();
    }
#endif
  }

  int numMsgsRecvd = sock.recvmmsg(msgs.data(), numPackets, flags, nullptr);
  if (numMsgsRecvd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // Exit, socket will notify us again when socket is readable.
      if (conn_->loopDetectorCallback) {
        conn_->readDebugState.noReadReason = NoReadReason::RETRIABLE_ERROR;
      }
      return;
    }
    // If we got a non-retriable error, we might have received
    // a packet that we could process, however let's just quit early.
    sock.pauseRead();
    if (conn_->loopDetectorCallback) {
      conn_->readDebugState.noReadReason = NoReadReason::NONRETRIABLE_ERROR;
    }
    return onReadError(folly::AsyncSocketException(
        folly::AsyncSocketException::INTERNAL_ERROR,
        "::recvmmsg() failed",
        errno));
  }

  CHECK_LE(numMsgsRecvd, numPackets);
  // Need to save our position so we can recycle the unused buffers.
  int i;
  for (i = 0; i < numMsgsRecvd; ++i) {
    size_t bytesRead = msgs[i].msg_len;
    if (bytesRead == 0) {
      // Empty datagram, this is probably garbage matching our tuple, we should
      // ignore such datagrams.
      freeBufs.emplace_back(std::move(readBuffers[i]));
      continue;
    }
    folly::AsyncUDPSocket::ReadCallback::OnDataAvailableParams params;
#ifdef FOLLY_HAVE_MSG_ERRQUEUE
    if (useGRO || useTS) {
      folly::AsyncUDPSocket::fromMsg(params, msgs[i].msg_hdr);

      // truncated
      if (bytesRead > readBufferSize) {
        bytesRead = readBufferSize;
        if (params.gro > 0) {
          bytesRead = bytesRead - bytesRead % params.gro;
        }
      }
    }
#endif
    totalData += bytesRead;

    if (!server) {
      server = folly::SocketAddress();
      auto* rawAddr = reinterpret_cast<sockaddr*>(&addrs[i]);
      server->setFromSockaddr(rawAddr, addrLen);
    }

    VLOG(10) << "Got data from socket peer=" << *server << " len=" << bytesRead;
    readBuffers[i]->append(bytesRead);
    if (params.gro > 0) {
      size_t len = bytesRead;
      size_t remaining = len;
      size_t offset = 0;
      size_t totalNumPackets =
          networkData.packets.size() + ((len + params.gro - 1) / params.gro);
      networkData.packets.reserve(totalNumPackets);
      while (remaining) {
        if (static_cast<int>(remaining) > params.gro) {
          auto tmp = readBuffers[i]->cloneOne();
          // start at offset
          tmp->trimStart(offset);
          // the actual len is len - offset now
          // leave gro bytes
          tmp->trimEnd(len - offset - params.gro);
          DCHECK_EQ(tmp->length(), params.gro);

          offset += params.gro;
          remaining -= params.gro;
          networkData.packets.emplace_back(std::move(tmp));
        } else {
          // do not clone the last packet
          // start at offset, use all the remaining data
          readBuffers[i]->trimStart(offset);
          DCHECK_EQ(readBuffers[i]->length(), remaining);
          remaining = 0;
          networkData.packets.emplace_back(std::move(readBuffers[i]));
        }
      }
    } else {
      networkData.packets.emplace_back(std::move(readBuffers[i]));
    }

    QUIC_TRACE(udp_recvd, *conn_, bytesRead);
    trackDatagramReceived(bytesRead);
  }
  for (; i < numPackets; i++) {
    freeBufs.emplace_back(std::move(readBuffers[i]));
    DCHECK(freeBufs.back() != nullptr);
  }
}

void QuicClientTransport::onNotifyDataAvailable(
    folly::AsyncUDPSocket& sock) noexcept {
  DCHECK(conn_) << "trying to receive packets without a connection";
  auto readBufferSize =
      conn_->transportSettings.maxRecvPacketSize * numGROBuffers_;
  const int numPackets = conn_->transportSettings.maxRecvBatchSize;

  NetworkData networkData;
  networkData.packets.reserve(numPackets);
  size_t totalData = 0;
  folly::Optional<folly::SocketAddress> server;

  if (conn_->transportSettings.shouldUseRecvmmsgForBatchRecv) {
    recvmmsgStorage_.resize(numPackets);
    recvMmsg(sock, readBufferSize, numPackets, networkData, server, totalData);
  } else {
    recvMsg(sock, readBufferSize, numPackets, networkData, server, totalData);
  }

  if (networkData.packets.empty()) {
    // recvMmsg and recvMsg might have already set the reason and counter
    if (conn_->loopDetectorCallback) {
      if (conn_->readDebugState.noReadReason == NoReadReason::READ_OK) {
        conn_->readDebugState.noReadReason = NoReadReason::EMPTY_DATA;
      }
      if (conn_->readDebugState.noReadReason != NoReadReason::READ_OK) {
        conn_->loopDetectorCallback->onSuspiciousReadLoops(
            ++conn_->readDebugState.loopCount,
            conn_->readDebugState.noReadReason);
      }
    }
    return;
  }
  DCHECK(server.has_value());
  // TODO: we can get better receive time accuracy than this, with
  // SO_TIMESTAMP or SIOCGSTAMP.
  auto packetReceiveTime = Clock::now();
  networkData.receiveTimePoint = packetReceiveTime;
  networkData.totalData = totalData;
  onNetworkData(*server, std::move(networkData));
}

void QuicClientTransport::
    happyEyeballsConnAttemptDelayTimeoutExpired() noexcept {
  QUIC_TRACE(happy_eyeballs, *conn_, "delay timer expired");
  // Declare 0-RTT data as lost so that they will be retransmitted over the
  // second socket.
  markZeroRttPacketsLost(*conn_, markPacketLoss);
  happyEyeballsStartSecondSocket(conn_->happyEyeballsState);
}

void QuicClientTransport::start(ConnectionCallback* cb) {
  if (happyEyeballsEnabled_) {
    // TODO Supply v4 delay amount from somewhere when we want to tune this
    startHappyEyeballs(
        *conn_,
        evb_,
        happyEyeballsCachedFamily_,
        happyEyeballsConnAttemptDelayTimeout_,
        happyEyeballsCachedFamily_ == AF_UNSPEC
            ? kHappyEyeballsV4Delay
            : kHappyEyeballsConnAttemptDelayWithCache,
        this,
        this,
        socketOptions_);
  }

  CHECK(conn_->peerAddress.isInitialized());

  if (conn_->qLogger) {
    conn_->qLogger->addTransportStateUpdate(kStart);
  }
  QUIC_TRACE(fst_trace, *conn_, "start");
  setConnectionCallback(cb);
  try {
    happyEyeballsSetUpSocket(
        *socket_,
        conn_->localAddress,
        conn_->peerAddress,
        conn_->transportSettings,
        this,
        this,
        socketOptions_);
    // adjust the GRO buffers
    adjustGROBuffers();
    startCryptoHandshake();
  } catch (const QuicTransportException& ex) {
    runOnEvbAsync([ex](auto self) {
      auto clientPtr = static_cast<QuicClientTransport*>(self.get());
      clientPtr->closeImpl(std::make_pair(
          QuicErrorCode(ex.errorCode()), std::string(ex.what())));
    });
  } catch (const QuicInternalException& ex) {
    runOnEvbAsync([ex](auto self) {
      auto clientPtr = static_cast<QuicClientTransport*>(self.get());
      clientPtr->closeImpl(std::make_pair(
          QuicErrorCode(ex.errorCode()), std::string(ex.what())));
    });
  } catch (const std::exception& ex) {
    LOG(ERROR) << "Connect failed " << ex.what();
    runOnEvbAsync([ex](auto self) {
      auto clientPtr = static_cast<QuicClientTransport*>(self.get());
      clientPtr->closeImpl(std::make_pair(
          QuicErrorCode(TransportErrorCode::INTERNAL_ERROR),
          std::string(ex.what())));
    });
  }
}

void QuicClientTransport::addNewPeerAddress(folly::SocketAddress peerAddress) {
  CHECK(peerAddress.isInitialized());

  if (happyEyeballsEnabled_) {
    conn_->udpSendPacketLen = std::min(
        conn_->udpSendPacketLen,
        (peerAddress.getFamily() == AF_INET6 ? kDefaultV6UDPSendPacketLen
                                             : kDefaultV4UDPSendPacketLen));
    happyEyeballsAddPeerAddress(*conn_, peerAddress);
    return;
  }

  conn_->udpSendPacketLen = peerAddress.getFamily() == AF_INET6
      ? kDefaultV6UDPSendPacketLen
      : kDefaultV4UDPSendPacketLen;
  conn_->originalPeerAddress = peerAddress;
  conn_->peerAddress = std::move(peerAddress);
}

void QuicClientTransport::setLocalAddress(folly::SocketAddress localAddress) {
  CHECK(localAddress.isInitialized());
  conn_->localAddress = std::move(localAddress);
}

void QuicClientTransport::setHappyEyeballsEnabled(bool happyEyeballsEnabled) {
  happyEyeballsEnabled_ = happyEyeballsEnabled;
}

void QuicClientTransport::setHappyEyeballsCachedFamily(
    sa_family_t cachedFamily) {
  happyEyeballsCachedFamily_ = cachedFamily;
}

void QuicClientTransport::addNewSocket(
    std::unique_ptr<folly::AsyncUDPSocket> socket) {
  happyEyeballsAddSocket(*conn_, std::move(socket));
}

void QuicClientTransport::setHostname(const std::string& hostname) {
  hostname_ = hostname;
}

void QuicClientTransport::setSelfOwning() {
  selfOwning_ = shared_from_this();
}

bool QuicClientTransport::setCustomTransportParameter(
    std::unique_ptr<CustomTransportParameter> customParam) {
  // check that the parameter id is in the "private parameter" range, as
  // described by the spec.
  if (static_cast<uint16_t>(customParam->getParameterId()) <
      kCustomTransportParameterThreshold) {
    return false;
  }

  // check to see that we haven't already added in a parameter with the
  // specified parameter id
  auto it = std::find_if(
      customTransportParameters_.begin(),
      customTransportParameters_.end(),
      [&customParam](const TransportParameter& param) {
        return param.parameter == customParam->getParameterId();
      });

  // if a match has been found, we return failure
  if (it != customTransportParameters_.end()) {
    return false;
  }

  customTransportParameters_.push_back(customParam->encode());
  return true;
}

void QuicClientTransport::setPartialReliabilityTransportParameter() {
  uint64_t partialReliabilitySetting = 0;
  if (conn_->transportSettings.partialReliabilityEnabled) {
    partialReliabilitySetting = 1;
  }
  auto partialReliabilityCustomParam =
      std::make_unique<CustomIntegralTransportParameter>(
          kPartialReliabilityParameterId, partialReliabilitySetting);

  if (!setCustomTransportParameter(std::move(partialReliabilityCustomParam))) {
    LOG(ERROR) << "failed to set partial reliability transport parameter";
  }
}

void QuicClientTransport::setD6DBasePMTUTransportParameter() {
  if (!conn_->transportSettings.d6dConfig.enabled) {
    return;
  }

  uint64_t basePMTUSetting =
      conn_->transportSettings.d6dConfig.advertisedBasePMTU;

  // Sanity check
  if (basePMTUSetting < kMinMaxUDPPayload ||
      basePMTUSetting > kDefaultMaxUDPPayload) {
    LOG(ERROR) << "insane base PMTU, skipping: " << basePMTUSetting;
    return;
  }

  auto basePMTUCustomParam = std::make_unique<CustomIntegralTransportParameter>(
      kD6DBasePMTUParameterId, basePMTUSetting);

  if (!setCustomTransportParameter(std::move(basePMTUCustomParam))) {
    LOG(ERROR) << "failed to set D6D base PMTU transport parameter";
  }
}

void QuicClientTransport::setD6DRaiseTimeoutTransportParameter() {
  if (!conn_->transportSettings.d6dConfig.enabled) {
    return;
  }

  std::chrono::seconds raiseTimeoutSetting =
      conn_->transportSettings.d6dConfig.advertisedRaiseTimeout;

  // Sanity check
  if (raiseTimeoutSetting < kMinD6DRaiseTimeout) {
    LOG(ERROR) << "d6d raise timeout exceeding lower bound, skipping: "
               << raiseTimeoutSetting.count();
  }

  auto raiseTimeoutCustomParam =
      std::make_unique<CustomIntegralTransportParameter>(
          kD6DRaiseTimeoutParameterId, raiseTimeoutSetting.count());

  if (!setCustomTransportParameter(std::move(raiseTimeoutCustomParam))) {
    LOG(ERROR) << "failed to set D6D raise timeout transport parameter";
  }
}

void QuicClientTransport::setD6DProbeTimeoutTransportParameter() {
  if (!conn_->transportSettings.d6dConfig.enabled) {
    return;
  }

  std::chrono::seconds probeTimeoutSetting =
      conn_->transportSettings.d6dConfig.advertisedProbeTimeout;

  // Sanity check
  if (probeTimeoutSetting < kMinD6DProbeTimeout) {
    LOG(ERROR) << "d6d probe timeout below lower bound, skipping: "
               << probeTimeoutSetting.count();
  }

  auto probeTimeoutCustomParam =
      std::make_unique<CustomIntegralTransportParameter>(
          kD6DProbeTimeoutParameterId, probeTimeoutSetting.count());

  if (!setCustomTransportParameter(std::move(probeTimeoutCustomParam))) {
    LOG(ERROR) << "failed to set D6D probe timeout transport parameter";
  }
}

void QuicClientTransport::adjustGROBuffers() {
  if (socket_ && conn_) {
    if (conn_->transportSettings.numGROBuffers_ > kDefaultNumGROBuffers) {
      socket_->setGRO(true);
      auto ret = socket_->getGRO();

      if (ret > 0) {
        numGROBuffers_ =
            (conn_->transportSettings.numGROBuffers_ < kMaxNumGROBuffers)
            ? conn_->transportSettings.numGROBuffers_
            : kMaxNumGROBuffers;
      }
    }
  }
}

void QuicClientTransport::closeTransport() {
  happyEyeballsConnAttemptDelayTimeout_.cancelTimeout();
}

void QuicClientTransport::unbindConnection() {
  selfOwning_ = nullptr;
}

void QuicClientTransport::setSupportedVersions(
    const std::vector<QuicVersion>& versions) {
  conn_->originalVersion = versions.at(0);
  auto params = conn_->readCodec->getCodecParameters();
  params.version = conn_->originalVersion.value();
  conn_->readCodec->setCodecParameters(params);
}

void QuicClientTransport::onNetworkSwitch(
    std::unique_ptr<folly::AsyncUDPSocket> newSock) {
  if (!conn_->oneRttWriteCipher) {
    return;
  }
  if (socket_ && newSock) {
    auto sock = std::move(socket_);
    socket_ = nullptr;
    sock->setErrMessageCallback(nullptr);
    sock->pauseRead();
    sock->close();

    socket_ = std::move(newSock);
    happyEyeballsSetUpSocket(
        *socket_,
        conn_->localAddress,
        conn_->peerAddress,
        conn_->transportSettings,
        this,
        this,
        socketOptions_);
    if (conn_->qLogger) {
      conn_->qLogger->addConnectionMigrationUpdate(true);
    }

    // adjust the GRO buffers
    adjustGROBuffers();
  }
}

void QuicClientTransport::setTransportStatsCallback(
    std::shared_ptr<QuicTransportStatsCallback> statsCallback) noexcept {
  CHECK(conn_);
  statsCallback_ = std::move(statsCallback);
  if (statsCallback_) {
    conn_->statsCallback = statsCallback_.get();
  } else {
    conn_->statsCallback = nullptr;
  }
}

void QuicClientTransport::trackDatagramReceived(size_t len) {
  if (conn_->qLogger) {
    conn_->qLogger->addDatagramReceived(len);
  }
  QUIC_STATS(statsCallback_, onPacketReceived);
  QUIC_STATS(statsCallback_, onRead, len);
}

void QuicClientTransport::maybeSendTransportKnobs() {
  if (!transportKnobsSent_ && hasWriteCipher()) {
    for (const auto& knob : conn_->transportSettings.knobs) {
      auto res =
          setKnob(knob.space, knob.id, folly::IOBuf::copyBuffer(knob.blob));
      if (res.hasError()) {
        if (res.error() != LocalErrorCode::KNOB_FRAME_UNSUPPORTED) {
          LOG(ERROR) << "Unexpected error while sending knob frames";
        }
        // No point in keep trying if transport does not support knob frame
        break;
      }
    }
    transportKnobsSent_ = true;
  }
}

} // namespace quic
