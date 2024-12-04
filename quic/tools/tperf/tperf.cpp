/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <glog/logging.h>

#include <folly/init/Init.h>
#include <folly/portability/GFlags.h>

#include <quic/tools/tperf/TperfClient.h>
#include <quic/tools/tperf/TperfServer.h>

DEFINE_string(host, "::1", "TPerf server hostname/IP");
DEFINE_int32(port, 6666, "TPerf server port");
DEFINE_string(mode, "server", "Mode to run in: 'client' or 'server'");
DEFINE_int32(duration, 10, "Duration of test in seconds");
DEFINE_uint64(
    block_size,
    1024 * 1024,
    "Amount of data written to stream each iteration");
DEFINE_uint64(writes_per_loop, 44, "Amount of socket writes per event loop");
DEFINE_uint64(window, 1024 * 1024, "Flow control window size");
DEFINE_bool(autotune_window, true, "Automatically increase the receive window");
DEFINE_string(congestion, "cubic", "newreno/cubic/bbr/none");
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
    "none",
    "none/time/rtt/ack: Pacing observer bucket type: per 3ms, per rtt or per ack");
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
DEFINE_bool(dsr, false, "if you want to debug perf");
DEFINE_bool(
    use_ack_receive_timestamps,
    false,
    "Replace the ACK frame with ACK_RECEIVE_TIMESTAMPS frame"
    "which carries the received packet timestamps");
DEFINE_uint32(
    max_ack_receive_timestamps_to_send,
    quic::kMaxReceivedPktsTimestampsStored,
    "Controls how many packet receive timestamps the peer should send");
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

namespace quic::tperf {

namespace {} // namespace

} // namespace quic::tperf

using namespace quic::tperf;

quic::CongestionControlType flagsToCongestionControlType(
    const std::string& congestionControlFlag) {
  auto ccType = quic::congestionControlStrToType(congestionControlFlag);
  if (!ccType) {
    throw std::invalid_argument(folly::to<std::string>(
        "Unknown congestion controller ", congestionControlFlag));
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

  if (FLAGS_mode == "server") {
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
        FLAGS_dsr,
        FLAGS_override_packet_size,
        FLAGS_latency_factor,
        FLAGS_use_ack_receive_timestamps,
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
        FLAGS_pacing_observer);
    server.start();
  } else if (FLAGS_mode == "client") {
    if (FLAGS_num_streams != 1) {
      LOG(ERROR) << "num_streams option is server only";
      return 1;
    }
    if (FLAGS_bytes_per_stream != 0) {
      LOG(ERROR) << "bytes_per_stream option is server only";
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
        FLAGS_max_ack_receive_timestamps_to_send,
        FLAGS_use_l4s_ecn,
        FLAGS_read_ecn,
        FLAGS_dscp);
    client.start();
  }
  return 0;
}
