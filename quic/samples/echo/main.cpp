/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <glog/logging.h>

#include <fizz/crypto/Utils.h>
#include <folly/init/Init.h>
#include <folly/portability/GFlags.h>

#include <quic/samples/echo/EchoClient.h>
#include <quic/samples/echo/EchoServer.h>

DEFINE_string(host, "::1", "Echo server hostname/IP");
DEFINE_int32(port, 6666, "Echo server port");
DEFINE_string(mode, "server", "Mode to run in: 'client' or 'server'");
DEFINE_string(
    token,
    "",
    "Client new token string to attach to connection initiation");
DEFINE_bool(use_datagrams, false, "Use QUIC datagrams to communicate");
DEFINE_int64(
    active_conn_id_limit,
    10,
    "Maximum number of active connection IDs a peer supports");
DEFINE_bool(enable_migration, true, "Enable/disable migration");

using namespace quic::samples;

int main(int argc, char* argv[]) {
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif
  gflags::ParseCommandLineFlags(&argc, &argv, false);
  folly::Init init(&argc, &argv);
  fizz::CryptoUtils::init();

  if (FLAGS_mode == "server") {
    EchoServer server(
        FLAGS_host,
        FLAGS_port,
        FLAGS_use_datagrams,
        FLAGS_active_conn_id_limit,
        FLAGS_enable_migration);
    server.start();
  } else if (FLAGS_mode == "client") {
    if (FLAGS_host.empty() || FLAGS_port == 0) {
      LOG(ERROR) << "EchoClient expected --host and --port";
      return -2;
    }
    EchoClient client(
        FLAGS_host,
        FLAGS_port,
        FLAGS_use_datagrams,
        FLAGS_active_conn_id_limit,
        FLAGS_enable_migration);
    client.start(FLAGS_token);
  } else {
    LOG(ERROR) << "Unknown mode specified: " << FLAGS_mode;
    return -1;
  }
  return 0;
}
