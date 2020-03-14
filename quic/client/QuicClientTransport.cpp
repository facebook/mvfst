/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/client/QuicClientTransport.h>

#include <folly/portability/Sockets.h>

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

#ifndef MSG_WAITFORONE
#define RECVMMSG_FLAGS 0
#else
#define RECVMMSG_FLAGS MSG_WAITFORONE
#endif

namespace quic {

QuicClientTransport::QuicClientTransport(
    folly::EventBase* evb,
    std::unique_ptr<folly::AsyncUDPSocket> socket,
    std::shared_ptr<ClientHandshakeFactory> handshakeFactory,
    size_t connectionIdSize)
    : QuicTransportBase(evb, std::move(socket)),
      happyEyeballsConnAttemptDelayTimeout_(this) {
  DCHECK(handshakeFactory);
  // TODO(T53612743) Only enforce that the initial destination connection id
  // is at least kMinInitialDestinationConnIdLength.
  // All subsequent destination connection ids should be in between
  // [kMinSelfConnectionIdSize, kMaxConnectionIdSize]
  DCHECK(
      connectionIdSize == 0 ||
      (connectionIdSize >= kMinInitialDestinationConnIdLength &&
       connectionIdSize <= kMaxConnectionIdSize));
  auto tempConn =
      std::make_unique<QuicClientConnectionState>(std::move(handshakeFactory));
  clientConn_ = tempConn.get();
  conn_.reset(tempConn.release());
  std::vector<uint8_t> connIdData(
      std::max(kMinInitialDestinationConnIdLength, connectionIdSize));
  folly::Random::secureRandom(connIdData.data(), connIdData.size());

  auto connId = ConnectionId(
      connectionIdSize == 0 ? std::vector<uint8_t>(0) : connIdData);
  conn_->clientConnectionId = connId;
  conn_->selfConnectionIds.emplace_back(
      std::move(connId), kInitialSequenceNumber);

  // Change destination connection to not be same as src connid to suss
  // out bugs.
  connIdData[0] ^= 0x1;
  clientConn_->initialDestinationConnectionId = ConnectionId(connIdData);
  conn_->readCodec = std::make_unique<QuicReadCodec>(QuicNodeType::Client);
  conn_->readCodec->setClientConnectionId(*conn_->clientConnectionId);
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
    auto& token = clientConn_->statelessResetToken;
    if (statelessReset->token == token) {
      VLOG(4) << "Received Stateless Reset " << *this;
      conn_->peerConnectionError = std::make_pair(
          QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
          toString(LocalErrorCode::CONNECTION_RESET).str());
      throw QuicInternalException("Peer reset", LocalErrorCode::NO_ERROR);
    }
    VLOG(4) << "Drop StatelessReset for bad connId or token " << *this;
  }

  RegularQuicPacket* regularOptional = parsedPacket.regularPacket();
  if (!regularOptional) {
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

  if (longHeader && longHeader->getHeaderType() == LongHeader::Types::Retry) {
    if (!clientConn_->retryToken.empty()) {
      VLOG(4) << "Server sent more than one retry packet";
      return;
    }

    // TODO (amsharma): Check if we have already received an initial packet
    // from the server. If so, discard it. Here are some ways in which I
    // could do this:
    // 1. Have a boolean flag initialPacketReceived_ that we set to true when
    //   we get an initial packet from the server. This seems a bit messy.
    // 2. Check for the presence of the oneRttWriteCipher and/or the
    //   oneRttReadCipher in the handshake layer. I think this might be a
    //   better approach, but I don't know if it is a good indicator that we've
    //   received an initial packet from the server.

    const ConnectionId* dstConnId =
        &(*clientConn_->initialDestinationConnectionId);
    if (conn_->serverConnectionId) {
      dstConnId = &(*conn_->serverConnectionId);
    }
    if (*longHeader->getOriginalDstConnId() != *dstConnId) {
      VLOG(4) << "Original destination connection id field in the retry "
              << "packet doesn't match the destination connection id from the "
              << "client's initial packet";
      return;
    }

    // Set the destination connection ID to be the value from the source
    // connection id of the retry packet
    clientConn_->initialDestinationConnectionId = longHeader->getSourceConnId();

    auto released = static_cast<QuicClientConnectionState*>(conn_.release());
    std::unique_ptr<QuicClientConnectionState> uniqueClient(released);
    auto tempConn = undoAllClientStateForRetry(std::move(uniqueClient));

    clientConn_ = tempConn.get();
    conn_.reset(tempConn.release());

    clientConn_->retryToken = longHeader->getToken();

    if (conn_->qLogger) {
      conn_->qLogger->addPacket(*regularOptional, packetSize);
    }

    startCryptoHandshake();
    return;
  }

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
      auto isSimple = quicFrame.asQuicSimpleFrame();
      auto isPing = isSimple ? isSimple->asPingFrame() : nullptr;
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
  auto outOfOrder =
      updateLargestReceivedPacketNum(ackState, packetNum, receiveTimePoint);

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
                // finished message. Thus we don't need to retransmit any of
                // the crypto data any longer.
                //
                // This will not cancel oneRttStream.
                //
                // TODO: replace this with a better solution later.
                cancelHandshakeCryptoStreamRetransmissions(*conn_->cryptoState);
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
                case QuicWriteFrame::Type::QuicSimpleFrame_E: {
                  const quic::QuicSimpleFrame simpleFrame =
                      *packetFrame.asQuicSimpleFrame();
                  updateSimpleFrameOnAck(*conn_, simpleFrame);
                  break;
                }
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
      case QuicFrame::Type::PaddingFrame_E: {
        break;
      }
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

  // Try reading bytes off of crypto, and performing a handshake.
  auto cryptoData = readDataFromCryptoStream(
      *getCryptoStream(*conn_->cryptoState, encryptionLevel));
  auto handshakeLayer = clientConn_->clientHandshakeLayer;
  if (cryptoData) {
    bool hadOneRttKey = conn_->oneRttWriteCipher != nullptr;
    handshakeLayer->doHandshake(std::move(cryptoData), encryptionLevel);
    bool oneRttKeyDerivationTriggered = false;
    if (!hadOneRttKey && conn_->oneRttWriteCipher) {
      oneRttKeyDerivationTriggered = true;
      updatePacingOnKeyEstablished(*conn_);
    }
    bool zeroRttRejected = handshakeLayer->getZeroRttRejected().value_or(false);
    if (zeroRttRejected) {
      if (conn_->qLogger) {
        conn_->qLogger->addTransportStateUpdate(kZeroRttRejected);
      }
      QUIC_TRACE(zero_rtt, *conn_, "rejected");
      removePsk();
    } else if (conn_->zeroRttWriteCipher) {
      if (conn_->qLogger) {
        conn_->qLogger->addTransportStateUpdate(kZeroRttAccepted);
      }
      QUIC_TRACE(zero_rtt, *conn_, "accepted");
    }
    bool shouldNegotiateParameters = false;
    if (clientConn_->zeroRttWriteCipher) {
      shouldNegotiateParameters =
          zeroRttRejected && (conn_->oneRttWriteCipher != nullptr);
    } else {
      shouldNegotiateParameters = oneRttKeyDerivationTriggered;
    }
    if (shouldNegotiateParameters) {
      auto originalPeerMaxOffset =
          conn_->flowControlState.peerAdvertisedMaxOffset;
      auto originalPeerInitialStreamOffsetBidiLocal =
          conn_->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal;
      auto originalPeerInitialStreamOffsetBidiRemote =
          conn_->flowControlState
              .peerAdvertisedInitialMaxStreamOffsetBidiRemote;
      auto originalPeerInitialStreamOffsetUni =
          conn_->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni;
      VLOG(10) << "Client negotiated transport params " << *this;
      auto serverParams = handshakeLayer->getServerTransportParams();
      if (!serverParams) {
        throw QuicTransportException(
            "No server transport params",
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
      }
      auto maxStreamsBidi = getIntegerParameter(
          TransportParameterId::initial_max_streams_bidi,
          serverParams->parameters);
      auto maxStreamsUni = getIntegerParameter(
          TransportParameterId::initial_max_streams_uni,
          serverParams->parameters);
      processServerInitialParams(
          *clientConn_, std::move(*serverParams), packetNum);

      cacheServerInitialParams(
          conn_->flowControlState.peerAdvertisedMaxOffset,
          conn_->flowControlState.peerAdvertisedInitialMaxStreamOffsetBidiLocal,
          conn_->flowControlState
              .peerAdvertisedInitialMaxStreamOffsetBidiRemote,
          conn_->flowControlState.peerAdvertisedInitialMaxStreamOffsetUni,
          maxStreamsBidi.value_or(0),
          maxStreamsUni.value_or(0));

      auto& statelessResetToken = clientConn_->statelessResetToken;
      if (statelessResetToken) {
        conn_->readCodec->setStatelessResetToken(*statelessResetToken);
      }
      if (zeroRttRejected) {
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
    if (zeroRttRejected) {
      // TODO: Make sure the alpn is the same, if not then do a full undo of the
      // state.
      clientConn_->zeroRttWriteCipher = nullptr;
      markZeroRttPacketsLost(*conn_, markPacketLoss);
    }
  }
  if (protectionLevel == ProtectionType::KeyPhaseZero ||
      protectionLevel == ProtectionType::KeyPhaseOne) {
    DCHECK(conn_->oneRttWriteCipher);
    clientConn_->clientHandshakeLayer->onRecvOneRttProtectedData();
    conn_->readCodec->onHandshakeDone(receiveTimePoint);
  }
  updateAckSendStateOnRecvPacket(
      *conn_,
      ackState,
      outOfOrder,
      pktHasRetransmittableData,
      pktHasCryptoData);
}

void QuicClientTransport::onReadData(
    const folly::SocketAddress& peer,
    NetworkDataSingle&& networkData) {
  if (closeState_ == CloseState::CLOSED) {
    // If we are closed, then we shoudn't process new network data.
    // TODO: we might want to process network data if we decide that we should
    // exit draining state early
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
}

void QuicClientTransport::writeData() {
  // TODO: replace with write in state machine.
  // TODO: change to draining when we move the client to have a draining state
  // as well.
  auto phase = clientConn_->clientHandshakeLayer->getPhase();
  QuicVersion version = conn_->version.value_or(*conn_->originalVersion);
  const ConnectionId& srcConnId = *conn_->clientConnectionId;
  const ConnectionId* destConnId =
      &(*clientConn_->initialDestinationConnectionId);
  if (conn_->serverConnectionId) {
    destConnId = &(*conn_->serverConnectionId);
  }
  if (closeState_ == CloseState::CLOSED) {
    // TODO: get rid of phase
    if (phase == ClientHandshake::Phase::Established &&
        conn_->oneRttWriteCipher) {
      CHECK(conn_->oneRttWriteHeaderCipher);
      writeShortClose(
          *socket_,
          *conn_,
          *destConnId /* dst */,
          conn_->localConnectionError,
          *conn_->oneRttWriteCipher,
          *conn_->oneRttWriteHeaderCipher);
    } else if (conn_->initialWriteCipher) {
      CHECK(conn_->initialHeaderCipher);
      writeLongClose(
          *socket_,
          *conn_,
          srcConnId /* src */,
          *destConnId /* dst */,
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
  CryptoStreamScheduler initialScheduler(
      *conn_, *getCryptoStream(*conn_->cryptoState, EncryptionLevel::Initial));
  CryptoStreamScheduler handshakeScheduler(
      *conn_,
      *getCryptoStream(*conn_->cryptoState, EncryptionLevel::Handshake));
  if (initialScheduler.hasData() ||
      (conn_->ackStates.initialAckState.needsToSendAckImmediately &&
       hasAcksToSchedule(conn_->ackStates.initialAckState))) {
    CHECK(conn_->initialWriteCipher);
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
  if (!packetLimit) {
    return;
  }
  if (handshakeScheduler.hasData() ||
      (conn_->ackStates.handshakeAckState.needsToSendAckImmediately &&
       hasAcksToSchedule(conn_->ackStates.handshakeAckState))) {
    CHECK(conn_->handshakeWriteCipher);
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
  if (!packetLimit) {
    return;
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
  if (!packetLimit) {
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

folly::Optional<QuicCachedPsk> QuicClientTransport::getPsk() {
  if (!hostname_ || !pskCache_) {
    return folly::none;
  }

  auto quicCachedPsk = pskCache_->getPsk(*hostname_);
  if (!quicCachedPsk) {
    return folly::none;
  }

  // TODO T32658838 better API to disable early data for current connection
  if (!conn_->transportSettings.attemptEarlyData) {
    quicCachedPsk->cachedPsk.maxEarlyDataSize = 0;
  } else if (
      earlyDataAppParamsValidator_ &&
      !earlyDataAppParamsValidator_(
          quicCachedPsk->cachedPsk.alpn,
          folly::IOBuf::copyBuffer(quicCachedPsk->appParams))) {
    quicCachedPsk->cachedPsk.maxEarlyDataSize = 0;
    // Do not remove psk here, will let application decide
  }

  return quicCachedPsk;
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

  // Look up psk and supply to handshake layer
  folly::Optional<QuicCachedPsk> quicCachedPsk = getPsk();
  folly::Optional<fizz::client::CachedPsk> cachedPsk;
  if (quicCachedPsk) {
    cachedPsk = std::move(quicCachedPsk->cachedPsk);
  }

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
      customTransportParameters_);
  conn_->transportParametersEncoded = true;
  handshakeLayer->connect(
      hostname_, std::move(cachedPsk), std::move(paramsExtension), this);

  if (clientConn_->zeroRttWriteCipher) {
    if (conn_->qLogger) {
      conn_->qLogger->addTransportStateUpdate(kZeroRttAttempted);
    }
    QUIC_TRACE(zero_rtt, *conn_, "attempted");

    // If zero rtt write cipher is derived, it means the cached psk was valid
    DCHECK(quicCachedPsk);

    auto& transportParams = quicCachedPsk->transportParams;
    cacheServerInitialParams(
        transportParams.initialMaxData,
        transportParams.initialMaxStreamDataBidiLocal,
        transportParams.initialMaxStreamDataBidiRemote,
        transportParams.initialMaxStreamDataUni,
        transportParams.initialMaxStreamsBidi,
        transportParams.initialMaxStreamsUni);
    updateTransportParamsFromCachedEarlyParams(*clientConn_, transportParams);
  }
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

void QuicClientTransport::cacheServerInitialParams(
    uint64_t peerAdvertisedInitialMaxData,
    uint64_t peerAdvertisedInitialMaxStreamDataBidiLocal,
    uint64_t peerAdvertisedInitialMaxStreamDataBidiRemote,
    uint64_t peerAdvertisedInitialMaxStreamDataUni,
    uint64_t peerAdvertisedInitialMaxStreamsBidi,
    uint64_t peerAdvertisedInitialMaxStreamUni) {
  serverInitialParamsSet_ = true;
  clientConn_->peerAdvertisedInitialMaxData = peerAdvertisedInitialMaxData;
  clientConn_->peerAdvertisedInitialMaxStreamDataBidiLocal =
      peerAdvertisedInitialMaxStreamDataBidiLocal;
  clientConn_->peerAdvertisedInitialMaxStreamDataBidiRemote =
      peerAdvertisedInitialMaxStreamDataBidiRemote;
  clientConn_->peerAdvertisedInitialMaxStreamDataUni =
      peerAdvertisedInitialMaxStreamDataUni;
  clientConn_->peerAdvertisedInitialMaxStreamsBidi =
      peerAdvertisedInitialMaxStreamsBidi;
  clientConn_->peerAdvertisedInitialMaxStreamsUni =
      peerAdvertisedInitialMaxStreamUni;
}

void QuicClientTransport::removePsk() {
  if (pskCache_ && hostname_) {
    pskCache_->removePsk(*hostname_);
  }
}

void QuicClientTransport::onNewCachedPsk(
    fizz::client::NewCachedPsk& newCachedPsk) noexcept {
  DCHECK(conn_->version.has_value());
  DCHECK(serverInitialParamsSet_);

  if (!pskCache_ || !hostname_) {
    return;
  }

  QuicCachedPsk quicCachedPsk;
  quicCachedPsk.cachedPsk = std::move(newCachedPsk.psk);

  quicCachedPsk.transportParams.idleTimeout = conn_->peerIdleTimeout.count();
  quicCachedPsk.transportParams.maxRecvPacketSize = conn_->udpSendPacketLen;
  quicCachedPsk.transportParams.initialMaxData =
      clientConn_->peerAdvertisedInitialMaxData;
  quicCachedPsk.transportParams.initialMaxStreamDataBidiLocal =
      clientConn_->peerAdvertisedInitialMaxStreamDataBidiLocal;
  quicCachedPsk.transportParams.initialMaxStreamDataBidiRemote =
      clientConn_->peerAdvertisedInitialMaxStreamDataBidiRemote;
  quicCachedPsk.transportParams.initialMaxStreamDataUni =
      clientConn_->peerAdvertisedInitialMaxStreamDataUni;
  quicCachedPsk.transportParams.initialMaxStreamsBidi =
      clientConn_->peerAdvertisedInitialMaxStreamsBidi;
  quicCachedPsk.transportParams.initialMaxStreamsUni =
      clientConn_->peerAdvertisedInitialMaxStreamsUni;

  if (earlyDataAppParamsGetter_) {
    auto appParams = earlyDataAppParamsGetter_();
    if (appParams) {
      quicCachedPsk.appParams = appParams->moveToFbString().toStdString();
    }
  }

  pskCache_->putPsk(*hostname_, std::move(quicCachedPsk));
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

void QuicClientTransport::getReadBuffer(void** buf, size_t* len) noexcept {
  DCHECK(conn_) << "trying to receive packets without a connection";
  auto readBufferSize = conn_->transportSettings.maxRecvPacketSize;
  readBuffer_ = folly::IOBuf::create(readBufferSize);
  *buf = readBuffer_->writableData();
  *len = readBufferSize;
}

void QuicClientTransport::onDataAvailable(
    const folly::SocketAddress& server,
    size_t len,
    bool truncated,
    folly::AsyncUDPSocket::ReadCallback::
        OnDataAvailableParams /*params*/) noexcept {
  VLOG(10) << "Got data from socket peer=" << server << " len=" << len;
  auto packetReceiveTime = Clock::now();
  Buf data = std::move(readBuffer_);

  if (truncated) {
    // This is an error, drop the packet.
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
  if (conn_->qLogger) {
    conn_->qLogger->addDatagramReceived(len);
  }
  NetworkData networkData(std::move(data), packetReceiveTime);
  onNetworkData(server, std::move(networkData));
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

    struct msghdr msg {};
    msg.msg_name = rawAddr;
    msg.msg_namelen = size_t(addrLen);
    msg.msg_iov = &vec;
    msg.msg_iovlen = 1;

    ssize_t ret = sock.recvmsg(&msg, 0);
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
    size_t bytesRead = size_t(ret);
    totalData += bytesRead;
    if (!server) {
      server = folly::SocketAddress();
      server->setFromSockaddr(rawAddr, addrLen);
    }
    VLOG(10) << "Got data from socket peer=" << *server << " len=" << bytesRead;
    readBuffer->append(bytesRead);
    networkData.packets.emplace_back(std::move(readBuffer));
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
  networkData.recvmmsgStorage.resize(numPackets);

  auto& msgs = networkData.recvmmsgStorage.msgs;
  auto& addrs = networkData.recvmmsgStorage.addrs;
  auto& readBuffers = networkData.recvmmsgStorage.readBuffers;
  auto& iovecs = networkData.recvmmsgStorage.iovecs;

  int i = 0;
  for (; i < numPackets; ++i) {
    // We create 1 buffer per packet so that it is not shared, this enables
    // us to decrypt in place. If the fizz decrypt api could decrypt in-place
    // even if shared, then we could allocate one giant IOBuf here.
    Buf readBuffer = folly::IOBuf::create(readBufferSize);
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
  }

  int numMsgsRecvd =
      sock.recvmmsg(msgs.data(), numPackets, RECVMMSG_FLAGS, nullptr);
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
  for (i = 0; i < numMsgsRecvd; ++i) {
    size_t bytesRead = msgs[i].msg_len;
    totalData += bytesRead;

    if (!server) {
      server = folly::SocketAddress();
      auto* rawAddr = reinterpret_cast<sockaddr*>(&addrs[i]);
      server->setFromSockaddr(rawAddr, addrLen);
    }

    VLOG(10) << "Got data from socket peer=" << *server << " len=" << bytesRead;
    readBuffers[i]->append(bytesRead);
    networkData.packets.emplace_back(std::move(readBuffers[i]));
    QUIC_TRACE(udp_recvd, *conn_, bytesRead);
    if (conn_->qLogger) {
      conn_->qLogger->addDatagramReceived(bytesRead);
    }
  }
}

void QuicClientTransport::onNotifyDataAvailable(
    folly::AsyncUDPSocket& sock) noexcept {
  DCHECK(conn_) << "trying to receive packets without a connection";
  auto readBufferSize = conn_->transportSettings.maxRecvPacketSize;
  const int numPackets = conn_->transportSettings.maxRecvBatchSize;

  NetworkData networkData;
  networkData.packets.reserve(numPackets);
  size_t totalData = 0;
  folly::Optional<folly::SocketAddress> server;

  if (conn_->transportSettings.shouldUseRecvmmsgForBatchRecv) {
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

void QuicClientTransport::setPskCache(std::shared_ptr<QuicPskCache> pskCache) {
  pskCache_ = std::move(pskCache);
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
    LOG(ERROR) << "failed to set partial reliability transport setting";
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

void QuicClientTransport::setQLogger(std::shared_ptr<QLogger> qLogger) {
  // TODO: For a client transport, client CID isn't dcid. But FileQLogger will
  // use dcid as file name.
  if (!qLogger) {
    return;
  }
  qLogger->setDcid(conn_->clientConnectionId);
  QuicTransportBase::setQLogger(std::move(qLogger));
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
  }
}
} // namespace quic
