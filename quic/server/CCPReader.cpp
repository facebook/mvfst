/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/server/CCPReader.h>

#include <quic/QuicConstants.h>
#include <quic/common/Timers.h>
#include <quic/congestion_control/QuicCCP.h>

#ifdef CCP_ENABLED
#include <ccp/ccp.h>
#include <ccp/ccp_error.h>
#endif

#include <folly/detail/IPAddress.h>

#define CCP_UNIX_BASE "/ccp/"
#define FROM_CCP "mvfst"
#define TO_CCP "portus"
#define CCP_MAX_MSG_SIZE 32678

namespace quic {

/**
 * In order to keep logic simple for callers of CCPReader (eg. QuicServer), this
 * implementation internalizes checks for whether or not ccp is enabled. If ccp
 * is enabled, the functions are defined as expected. If not, the functions are
 * just empty stubs that ignore their args and do nothing (see bottom).
 */
#ifdef CCP_ENABLED

/*
 * libccp callbacks
 *
 * These functions are not called by CCPReader directly. We pass a reference of
 * them to libccp so that it has a simple interface to modify state (eg. cwnd)
 * within the datapath as necessary.
 */
extern "C" {

/**
 * In libccp, all time is relative to process start.
 * NOTE: This is a global variable (as opposed to a field in CCPReader), because
 * the time functions, such as libccp::now, are stateless and take no
 * parameters.
 * TODO: in a future version, libccp should pass a pointer to the datapath
 * struct, so we can recover the corresponding CCPReader and keep this variable
 * as a field there instead.
 */
uint64_t init_time_ns = 0;

void _ccp_set_cwnd(struct ccp_connection* conn, uint32_t cwnd) {
  // Look up the CCP cc algorithm instance for this connection
  CCP* alg = (CCP*)ccp_get_impl(conn);
  alg->setCongestionWindow(cwnd);
}

void _ccp_set_rate_abs(struct ccp_connection* conn, uint32_t rate) {
  CCP* alg = (CCP*)ccp_get_impl(conn);
  alg->setPacingRate(rate);
}

int _ccp_send_msg(struct ccp_connection* conn, char* msg, int msg_size) {
  std::unique_ptr<folly::IOBuf> buf = folly::IOBuf::wrapBuffer(msg, msg_size);
  // Since this function is called by libccp, we are not within the CCPReader
  // and thus need to look up a reference to it. This is stored within the
  // datapath object created in CCPReader::try_initialize.
  CCPReader* reader = (CCPReader*)conn->datapath->impl;
  auto ret = reader->writeOwnedBuffer(std::move(buf));
  if (ret < 0) {
    LOG(ERROR) << "ccp_send_msg failed ret=" << ret << " errno=" << errno;
  }
  return ret;
}

static void _ccp_log(
    struct ccp_datapath* /*dp*/,
    enum ccp_log_level level,
    const char* msg,
    int /*msg_size*/) {
  LOG(ERROR) << "[libccp." << level << "] " << msg;
}

// The next 3 functions are used to provide libccp with a sense of time.
// It uses these functions to implement timers, so the timers can only be
// as accurate as the notion of time provided here.
uint64_t _ccp_now_usecs() {
  struct timespec now;
  uint64_t now_ns, now_us;

  clock_gettime(CLOCK_MONOTONIC, &now);

  now_ns = (1000000000L * now.tv_sec) + now.tv_nsec;
  if (init_time_ns == 0) {
    init_time_ns = now_ns;
  }

  now_us = ((now_ns - init_time_ns) / 1000) & 0xffffffff;
  return now_us;
}

uint64_t _ccp_since_usecs(uint64_t then) {
  return _ccp_now_usecs() - then;
}

uint64_t _ccp_after_usecs(uint64_t usecs) {
  return _ccp_now_usecs() + usecs;
}
} // end libccp callbacks

CCPReader::CCPReader() = default;

void CCPReader::try_initialize(
    folly::EventBase* evb,
    uint64_t ccpId,
    uint64_t parentServerId,
    uint8_t parentWorkerId) {
  evb_ = evb;
  ccpId_ = ccpId;
  serverId_ = parentServerId;
  workerId_ = parentWorkerId;

  // Even though it is technically called an Async*UDP*Socket by folly,
  // this is really a unix socket!
  ccpSocket_ = std::make_unique<folly::AsyncUDPSocket>(evb_);

  bind();

  // libccp asks us to allocate this struct manually (as opposed to allocating
  // it internally as it does for other things), to allow the max connections to
  // be configurable. This array is used by libccp to keep track of all the
  // connections that are currently active. The index is the connection id.
  struct ccp_connection* active_connections = (struct ccp_connection*)calloc(
      MAX_CONCURRENT_CONNECTIONS_LIBCCP, sizeof(struct ccp_connection));
  if (active_connections == nullptr) {
    LOG(ERROR) << "[ccp] failed to allocate per-connection data structure";
    return;
  }

  // Giving libccp a reference to all of the callbacks
  ccpDatapath_.set_cwnd = &_ccp_set_cwnd;
  ccpDatapath_.set_rate_abs = &_ccp_set_rate_abs;
  ccpDatapath_.send_msg = &_ccp_send_msg;
  ccpDatapath_.log = &_ccp_log;
  ccpDatapath_.now = &_ccp_now_usecs;
  ccpDatapath_.since_usecs = &_ccp_since_usecs;
  ccpDatapath_.after_usecs = &_ccp_after_usecs;

  ccpDatapath_.impl = (void*)this;
  ccpDatapath_.ccp_active_connections = active_connections;
  ccpDatapath_.max_connections = MAX_CONCURRENT_CONNECTIONS_LIBCCP;
  ccpDatapath_.max_programs = MAX_DATAPATH_PROGRAMS_LIBCCP;
  ccpDatapath_.fto_us = FALLBACK_TIMEOUT_US_LIBCCP;

  // This function registers us (QuicServerWorker+CCPReader) as a "datapath"
  // within libccp. Libccp itself is stateless, so all of our state is
  // maintained in this struct and thus must be passed to any future calls to
  // libccp.
  int ret = ccp_init(&ccpDatapath_);
  if (ret < 0) {
    LOG(ERROR) << "[ccp] ccp_init failed ret=" << ret;
    throw std::runtime_error("internal bug: unable to interface with libccp");
  }
}

int CCPReader::connect() {
  // This message registers us with CCP. CCP ignores messages from
  // datapaths that have not yet registered with it. It identifies a datapath
  // by the sending address (/ccp/mvfst{id}).
  char ready_buf[READY_MSG_SIZE];
  int wrote = write_ready_msg(ready_buf, READY_MSG_SIZE, workerId_);
  std::unique_ptr<folly::IOBuf> ready_msg =
      folly::IOBuf::wrapBuffer(ready_buf, wrote);
  int ret = writeOwnedBuffer(std::move(ready_msg));
  // Since we start ccp within a separate thread from QuicServer, its possible
  // that it hasn't been scheduled yet when we send this message, in which case
  // we will get an unable to connet to socket error (111). If this happens,
  // we return a failure and expected the caller to wait and retry later.
  // If we can't connect after a few tries then something is probably wrong
  // with CCP and we should give up.
  if (ret < 0) {
    LOG(ERROR) << "[ccp] write_ready_msg failed ret=" << ret
               << " errno=" << errno;
  } else {
    LOG(INFO) << "[ccp] write_ready_msg success";
    initialized_ = true;
  }
  return ret;
}

folly::EventBase* CCPReader::getEventBase() const {
  return evb_;
}

/**
 * We communicate with CCP via unix domain sockets.
 * CCP owns the address /ccp/portus
 * Each QuicServerWorker has its own address, distinguished by worker id:
 * ccp/mvfst{id}
 */
void CCPReader::bind() {
  CHECK(ccpSocket_);

  // In order to prevent permission issues in production environments, we use
  // "abstract" sockets, which do not actually create an entry in the
  // filesystem. An abstract socket is created by prepending a nullbyte to the
  // desired path name. FYI, when displayed by system utilities, abstract socket
  // names appear with an @ as the first character to denote the null byte.
  std::string recvPath(1, 0);
  recvPath.append(CCP_UNIX_BASE);
  recvPath.append(
      std::to_string(ccpId_) + "/" + std::to_string(serverId_) + "/");
  recvPath.append(FROM_CCP);
  recvPath.append(std::to_string(workerId_));
  recvAddr_.setFromPath(recvPath);
  ccpSocket_->bind(recvAddr_);

  // Again we start the address with a null byte here to make it abstract
  // Since these are connectionless sockets, we don't need to connect to this
  // address.
  std::string sendPath(1, 0);
  sendPath.append(CCP_UNIX_BASE);
  sendPath.append(std::to_string(ccpId_) + "/");
  sendPath.append(TO_CCP);
  sendAddr_.setFromPath(sendPath);
}

void CCPReader::start() {
  ccpSocket_->resumeRead(this);
}

void CCPReader::pauseRead() {
  CHECK(ccpSocket_);
  ccpSocket_->pauseRead();
}

void CCPReader::getReadBuffer(void** buf, size_t* len) noexcept {
  // TODO should this be initialized once in the constructor and re-used here?
  readBuffer_ = folly::IOBuf::create(CCP_MAX_MSG_SIZE);
  *buf = readBuffer_->writableData();
  *len = CCP_MAX_MSG_SIZE;
}

void CCPReader::onDataAvailable(
    const folly::SocketAddress& /*client*/,
    size_t len,
    bool truncated,
    OnDataAvailableParams /*params*/) noexcept {
  // TODO if read buffer is re-used, shouldn't move it here
  // Move readBuffer_ first to get rid of it immediately so that if we return
  // early, we've flushed it.
  Buf data = std::move(readBuffer_);
  if (truncated || len <= 0) {
    // This is an error, drop the packet.
    return;
  }

  // TODO is this needed?
  // data->append(len);
  char* buf = (char*)data->data();
  int ret = ccp_read_msg(&ccpDatapath_, buf, len);

  // After a connection ends, we may get 1 more message from ccp about it,
  // but we've already removed it from our local list of connections,
  // so libccp will return LIBCCP_UNKNOWN_CONNECTION, which we can ignore
  if (ret < 0 && ret != LIBCCP_UNKNOWN_CONNECTION) {
    LOG(ERROR) << "ccp_read_msg failed ret=" << ret;
  }
}

void CCPReader::onReadError(const folly::AsyncSocketException& ex) noexcept {
  LOG(ERROR) << "ccpReader onReadError: " << ex.what();
}

void CCPReader::onReadClosed() noexcept {
  shutdown();
}

ssize_t CCPReader::writeOwnedBuffer(std::unique_ptr<folly::IOBuf> buf) {
  return ccpSocket_->write(sendAddr_, buf);
}

uint8_t CCPReader::getWorkerId() const noexcept {
  return workerId_;
}

struct ccp_datapath* CCPReader::getDatapath() noexcept {
  return initialized_ ? &ccpDatapath_ : nullptr;
}

void CCPReader::shutdown() {
  if (ccpSocket_) {
    try {
      ccpSocket_->pauseRead();
      ccpSocket_->close();
    } catch (...) {
    }
    ccpSocket_ = nullptr;
  }
  if (ccpDatapath_.ccp_active_connections) {
    free(ccpDatapath_.ccp_active_connections);
  }
  ccp_free(&ccpDatapath_);
}

CCPReader::~CCPReader() {
  // We allocated the list of active connections and ccp_datapath struct,
  // so we are responsible for freeing them
  shutdown();
}

#else // Empty method placeholders for when ccp is not enabled:

CCPReader::CCPReader() = default;
void CCPReader::try_initialize(
    folly::EventBase* evb,
    uint64_t,
    uint64_t,
    uint8_t) {
  evb_ = evb;
}
int CCPReader::connect() {
  return 0;
}
folly::EventBase* CCPReader::getEventBase() const {
  return evb_;
}
void CCPReader::bind() {}
void CCPReader::start() {}
void CCPReader::pauseRead() {}
void CCPReader::getReadBuffer(void**, size_t*) noexcept {}
void CCPReader::onDataAvailable(
    const folly::SocketAddress&,
    size_t,
    bool,
    OnDataAvailableParams) noexcept {}
void CCPReader::onReadError(const folly::AsyncSocketException&) noexcept {}
void CCPReader::onReadClosed() noexcept {}
ssize_t CCPReader::writeOwnedBuffer(std::unique_ptr<folly::IOBuf>) {
  return 0;
}
uint8_t CCPReader::getWorkerId() const noexcept {
  return workerId_;
}
void CCPReader::shutdown() {}
CCPReader::~CCPReader() = default;

#endif

} // namespace quic
