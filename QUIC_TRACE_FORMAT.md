## Quic Trace

All the QUIC_TRACE() functions in the code are used to generate traces at run-time. These traces are in arbitrary format. This documents covers different traces and what the values represent.  We are in the process of deprecating these traces in favor of QLog.

The following example is a Quic trace from a real connection in Facebook's production network. We have an internal tool to format Quic traces into such columned file.

```
reltime ||    client_conn_id ||     server_conn_id ||     event ||              value
148401640306  681b2cedd6da02d7      42bb929f9a80dbd2      packet_sent           InitialSpace, 1, 142, 1, 0, 1
148401640328  681b2cedd6da02d7      42bb929f9a80dbd2      fst_trace             transport ready
148401740661  681b2cedd6da02d7      42bb929f9a80dbd2      packet_acked          InitialSpace, 0
148401740669  681b2cedd6da02d7      42bb929f9a80dbd2      packet_acked          InitialSpace, 1
148401743641  681b2cedd6da02d7      42bb929f9a80dbd2      update_rtt            102679, 616, 100324, 100617
148401743797  681b2cedd6da02d7      42bb929f9a80dbd2      bbr_applimited        900802566008505
148401776120  681b2cedd6da02d7      42bb929f9a80dbd2      packet_sent           AppDataSpace, 1, 32, 0, 1, 1
148401955772  681b2cedd6da02d7      42bb929f9a80dbd2      packet_recvd          1, 405
148402239753  681b2cedd6da02d7      42bb929f9a80dbd2      stream_event          headers, 0, 494

```

*reltime* is a timestamp in microseconds. *client_conn_id* and *server_conn_id* are Quic connection IDs assigned by client and server for this connection. A typical Quic trace contains an *event* name and a series of *values*. One special event is *fst_trace*. The value of fst_trace event is an arbitrary string. For all the other events, the values are defined as follow:

| Event | Values | Comment |
|-------|--------|---------|
| bbr_ack | BbrState, BbrRecoveryState, CwndBytes, LastUpdatedBDP, SendQuantum, InflightBytes | See BBR RFC for SendQuantum |
| bbr_appidle | IsIdle | App becomes idle |
| bbr_appunlimited | LargestAckedPacket, AppLimitedExitTargetTimeSinceEpoch | BBR exits app-limited |
| bbr_applimited | AppLimitedExitTargetTimeSinceEpoch | BBR becomes app-limited |
| bbr_persistent_congestion | BbrState, BbrRecoveryState, RecoveryWindow, InflightBytes | |
| conn_close | Drain, SendCloseFrame, CloseReason, Error | |
| copa_ack | CwndBytes, InflightBytes | |
| copa_loss | CwndBytes, InflightBytes | |
| cubic_appidle | IsAppIdle, EventTimeSinceEpoch, LastCwndReductionTimeSinceEpoch | |
| cubic_ack | CubicState, CwndBytes, InflightBytes, LastMaxCwndBytes | |
| cubic_loss | CubicState, CwndBytes, InflightBytes, LastMaxCwndBytes | |
| cubic_persistent_congestion | CubicState, CwndBytes, InflightBytes, LastMaxCwndBytes | |
| cubic_remove_inflight | CubicState, CwndBytes, InflightBytes, LastMaxCwndBytes | We removed bytes from Cubic inflightBytes without calling loss |
| cubic_steady_cwnd | CwndBytes, Delta, TimeToOrigin, TimeElapsed | Cubic steady state cwnd calculation. See Cubic paper for these definition |
| cwnd_may_block | WritableBytes, CwndBytes | Connection will be cwnd-blocked if App sends again |
| flow_control_event | "tx_conn", AdvertisedOffset | We send a window update |
| flow_control_event | "conn_blocked", StreamId, StreamWriteOffset | Connection blocked by flow control |
| flow_control_event | "stream_blocked", StreamId, PeerAdvertisedMaxOffset | Stream blocked by flow  control  |
| flow_control_event | "rx_stream", StreamId, MaximumData, PacketNum | We  received a stream window  update  |
| flow_control_event | "rx_conn", MaximumData, PacketNum | We received a connection window update |
| fst_trace | (Arbitrary self-explanable trace string) | |
| holb_time | StreamId, HolbTime, HolbCount | HOLB = Head-of-line blocking. |
| handshake_alarm | LargestSentPacketNumber, HandshakeAlarmCount, OutstandingHandshakePacketsCount, OutstandingPacketsCount | This is the event of Crypto timer fired. |
| happy_eyeballs | (Self-explanable trace string) |  |
| packet_acked | PacketNumberSpace, PacketNumber | |
| packet_buffered | PacketNumber, ProtectionLevel, PacketSize | This only happens when we receive data but don't have the keys to decrypt them yet |
| packet_drop | DropReason | |
| packet_recvd | PacketNumberSpace, PacketNumber, PacketSize | |
| pacing_update | PacingInterval, BurstSize | |
| packets_lost | LargestLostPacketNumber, LostBytes, LostPackets | |
| packet_acked | PacketNumberSpace, PacketNumber | |
| packet_sent | PacketNumberSpace, PacketNumber, PacketSize, IsHandshake, IsPureAck, IsAppLimited | |
| pto_alarm | LargestSent, PTOCount, OutstandingPacketsCount | PTO = RTO. Time is retransmission timeout event. |
| revd_close | Error | |
| stream_event | (Arbitrary app level trace) | |
| transport_data | TotalBytesSent, TotalBytesRecvd, ConnectionWriteOffset, ConnectionReadOffset, CurrentWriteBuffer, BytesRetransmittedDueToLoss, AppBytesRetransmisttedDueToTimeout, AllBytesRetransmittedDueToTimeout, CryptoBytesSent, CryptoBytesReceived | |
| udp_recvd | PacketSize | |
| update_rtt | CurrentRttSample, AckDelay, MinimalRtt, Srtt | |
| zero_rtt | Accepted/Rejected/Attempted | |
