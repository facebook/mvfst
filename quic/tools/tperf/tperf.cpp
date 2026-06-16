/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>

#include <folly/init/Init.h>
#include <folly/portability/GFlags.h>

#include <quic/tools/tperf/TperfClient.h>
#include <quic/tools/tperf/TperfServer.h>
#include <quic/tools/tperf/TperfTcp.h>

DEFINE_string(host, "::1", "TPerf server hostname/IP");
DEFINE_int32(port, 6666, "TPerf server port");
DEFINE_string(mode, "server", "Mode to run in: 'client' or 'server'");
DEFINE_string(
    transport,
    "quic",
    "Transport to run: 'quic' or 'tcp'. TCP mode uses TLS over TCP via Fizz.");
DEFINE_int32(duration, 10, "Duration of test in seconds");
DEFINE_uint64(
    block_size,
    1024 * 1024,
    "Amount of data written to stream each iteration");
DEFINE_uint64(writes_per_loop, 44, "Amount of socket writes per event loop");
DEFINE_uint64(window, 1024 * 1024, "Flow control window size");
DEFINE_bool(autotune_window, true, "Automatically increase the receive window");
DEFINE_string(congestion, "cubic", "newreno/cubic/bbr/std::nullopt");
DEFINE_bool(pacing, false, "Enable pacing");
DEFINE_uint64(
    max_pacing_rate,
    std::numeric_limits<uint64_t>::max(),
    "Max pacing rate to use in bytes per second");
DEFINE_bool(gso, true, "Enable GSO writes to the socket");
DEFINE_uint32(
    client_transport_timer_resolution_ms,
    1,
    "Timer resolution for Ack and Loss timeout in client transport");
DEFINE_string(
    server_qlogger_path,
    "",
    "Path to the directory where qlog files will be written. File will be named"
    " as <CID>.qlog where CID is the DCID from client's perspective.");
DEFINE_uint32(
    max_cwnd_mss,
    quic::kLargeMaxCwndInMss,
    "Max cwnd in the unit of mss");
DEFINE_uint32(num_streams, 1, "Number of streams to send on simultaneously");
DEFINE_uint64(
    bytes_per_stream,
    0,
    "Maximum number of bytes per stream. "
    "0 (the default) means the stream lives for the whole duration of the test.");
DEFINE_string(
    pacing_observer,
    "std::nullopt",
    "std::nullopt/time/rtt/ack: Pacing observer bucket type: per 3ms, per rtt or per ack");
DEFINE_uint32(
    max_receive_packet_size,
    quic::kDefaultMaxUDPPayload,
    "Maximum packet size to advertise to the peer.");
DEFINE_bool(
    override_packet_size,
    true,
    "Sender trusts the peer's advertised max packet size.");
DEFINE_bool(use_inplace_write, true, "Data path type");
DEFINE_double(latency_factor, 0.5, "Latency factor (delta) for Copa");
DEFINE_uint32(
    num_server_worker,
    1,
    "Max number of mvfst server worker threads");
DEFINE_bool(log_rtt_sample, false, "Log rtt sample events");
DEFINE_bool(log_loss, false, "Log packet loss events");
DEFINE_bool(log_app_rate_limited, false, "Log app rate limited events");
DEFINE_string(
    transport_knob_params,
    "",
    "JSON-serialized dictionary of transport knob params");
DEFINE_bool(
    use_ack_receive_timestamps,
    false,
    "Request the peer to attach receive timestamps to outgoing ACKs. By "
    "default the legacy mvfst transport parameters and 0xB0/0xB1 wire "
    "format are advertised. Combine with --use_draft02_ack_receive_timestamps "
    "to also advertise draft-ietf-quic-receive-ts-02; when both formats are "
    "negotiated end-to-end, the scheduler prefers draft-02.");
DEFINE_bool(
    use_draft02_ack_receive_timestamps,
    false,
    "Advertise draft-ietf-quic-receive-ts-02 receive-timestamp transport "
    "parameters (0x4ac07 / 0x4ac26) and accept the 0x03178307/0x03178308 "
    "wire format. Implies requesting receive timestamps from the peer; can "
    "be set without --use_ack_receive_timestamps for a draft-02-only run.");
DEFINE_bool(
    advertise_legacy_ack_receive_timestamps,
    true,
    "Advertise the legacy mvfst receive-timestamp transport parameters "
    "(0xff0a001 / 0xff0a002 / 0xff0a003). Set to false to migrate to a "
    "draft-02-only peer. Applies whenever --use_ack_receive_timestamps or "
    "--use_draft02_ack_receive_timestamps is set.");
DEFINE_bool(
    send_draft02_ack_receive_timestamps,
    true,
    "Per-direction send opt-out for draft-02 ACK_RECEIVE_TIMESTAMPS. When "
    "false, this endpoint will NOT send draft-02 frames even if the peer "
    "advertised; useful for asymmetric setups where this endpoint wants to "
    "receive timestamps but not send any. No effect on the legacy mvfst "
    "wire format.");
DEFINE_uint32(
    max_ack_receive_timestamps_to_send,
    quic::kMaxReceivedPktsTimestampsStored,
    "Controls how many packet receive timestamps the peer should send "
    "(applies to both legacy and draft-02 advertisements).");
DEFINE_bool(use_l4s_ecn, false, "Whether to use L4S for ECN marking");
DEFINE_bool(
    read_ecn,
    false,
    "Whether to read and echo ecn marking from ingress packets");
DEFINE_uint32(dscp, 0, "DSCP value to use for outgoing packets");
DEFINE_uint32(
    burst_deadline_ms,
    0,
    "If > 0, server will send bursts of data of size=block_size with a deadline of burst_deadline_ms milliseconds");
DEFINE_uint64(
    static_cwnd_bytes,
    quic::kInitCwndInMss* quic::kDefaultUDPSendPacketLen,
    "If the StaticCwnd congestion controller is used, this is the static cwnd in bytes");
DEFINE_string(
    pacer_interval_source,
    "std::nullopt",
    "If the StaticCwnd congestion controller is used with a pacer, this is the rtt that will be used to updated the pacer. (mrtt, lrtt, srtt, std::nullopt)");

namespace quic::tperf {

namespace {} // namespace

} // namespace quic::tperf

using namespace quic::tperf;

enum class TperfTransportMode : uint8_t { Quic, Tcp };

TperfTransportMode flagsToTransportMode(const std::string& transportFlag) {
  if (transportFlag == "quic") {
    return TperfTransportMode::Quic;
  }
  if (transportFlag == "tcp") {
    return TperfTransportMode::Tcp;
  }
  throw std::invalid_argument(
      fmt::format("Unknown transport {}", transportFlag));
}

quic::CongestionControlType flagsToCongestionControlType(
    const std::string& congestionControlFlag) {
  auto ccType = quic::congestionControlStrToType(congestionControlFlag);
  if (!ccType) {
    throw std::invalid_argument(
        fmt::format("Unknown congestion controller {}", congestionControlFlag));
  }
  return *ccType;
}

int main(int argc, char* argv[]) {
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif
  gflags::ParseCommandLineFlags(&argc, &argv, false);
  folly::Init init(&argc, &argv);

  TperfTransportMode transportMode = TperfTransportMode::Quic;
  try {
    transportMode = flagsToTransportMode(FLAGS_transport);
  } catch (const std::invalid_argument& ex) {
    MVLOG_ERROR << ex.what();
    return 1;
  }
  if (FLAGS_mode == "server") {
    if (transportMode == TperfTransportMode::Tcp) {
      TPerfTcpServer server(
          TPerfTcpServerConfig{
              .host = FLAGS_host,
              .port = static_cast<uint16_t>(FLAGS_port),
              .blockSize = FLAGS_block_size,
              .writesPerLoop = FLAGS_writes_per_loop,
          });
      server.start();
      return 0;
    }
    TPerfServer server(
        FLAGS_host,
        FLAGS_port,
        FLAGS_block_size,
        FLAGS_writes_per_loop,
        flagsToCongestionControlType(FLAGS_congestion),
        FLAGS_gso,
        FLAGS_max_cwnd_mss,
        FLAGS_pacing,
        FLAGS_num_streams,
        FLAGS_bytes_per_stream,
        FLAGS_max_receive_packet_size,
        FLAGS_use_inplace_write,
        FLAGS_override_packet_size,
        FLAGS_latency_factor,
        FLAGS_use_ack_receive_timestamps,
        FLAGS_use_draft02_ack_receive_timestamps,
        FLAGS_advertise_legacy_ack_receive_timestamps,
        FLAGS_send_draft02_ack_receive_timestamps,
        FLAGS_max_ack_receive_timestamps_to_send,
        FLAGS_use_l4s_ecn,
        FLAGS_read_ecn,
        FLAGS_dscp,
        FLAGS_num_server_worker,
        FLAGS_burst_deadline_ms,
        FLAGS_max_pacing_rate,
        FLAGS_log_app_rate_limited,
        FLAGS_log_loss,
        FLAGS_log_rtt_sample,
        FLAGS_server_qlogger_path,
        FLAGS_pacing_observer,
        nullptr, // DoneCallback
        TPerfServer::StaticCwndConfig(
            FLAGS_static_cwnd_bytes, FLAGS_pacer_interval_source));
    server.start();
  } else if (FLAGS_mode == "client") {
    if (transportMode == TperfTransportMode::Tcp) {
      TPerfTcpClient client(
          TPerfTcpClientConfig{
              .host = FLAGS_host,
              .port = static_cast<uint16_t>(FLAGS_port),
              .duration = FLAGS_duration,
          });
      client.start();
      return 0;
    }
    if (FLAGS_num_streams != 1) {
      MVLOG_ERROR << "num_streams option is server only";
      return 1;
    }
    if (FLAGS_bytes_per_stream != 0) {
      MVLOG_ERROR << "bytes_per_stream option is server only";
      return 1;
    }
    TPerfClient client(
        FLAGS_host,
        FLAGS_port,
        std::chrono::milliseconds(FLAGS_client_transport_timer_resolution_ms),
        FLAGS_duration,
        FLAGS_window,
        FLAGS_autotune_window,
        FLAGS_gso,
        flagsToCongestionControlType(FLAGS_congestion),
        FLAGS_max_receive_packet_size,
        FLAGS_use_inplace_write,
        FLAGS_transport_knob_params,
        FLAGS_use_ack_receive_timestamps,
        FLAGS_use_draft02_ack_receive_timestamps,
        FLAGS_advertise_legacy_ack_receive_timestamps,
        FLAGS_send_draft02_ack_receive_timestamps,
        FLAGS_max_ack_receive_timestamps_to_send,
        FLAGS_use_l4s_ecn,
        FLAGS_read_ecn,
        FLAGS_dscp);
    client.start();
  } else {
    MVLOG_ERROR << "Unknown mode " << FLAGS_mode;
    return 1;
  }
  return 0;
}
