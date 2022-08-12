/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/io/async/EventBase.h>
#include <folly/io/async/EventBaseBackendBase.h>
#include <quic/server/QuicServer.h>

namespace quic {

#if _WIN32
#include <mmsystem.h>
#include <timeapi.h>
#pragma comment(lib, "winmm.lib")

struct GetBetterWindowsTimers {
  GetBetterWindowsTimers() {
    CHECK_EQ(timeBeginPeriod(1), TIMERR_NOERROR);
  }
  ~GetBetterWindowsTimers() {
    timeEndPeriod(1);
  }
};

GetBetterWindowsTimers timerGetter;

class WindowsEventBaseBackend : public folly::EventBaseBackendBase {
 public:
  WindowsEventBaseBackend();
  explicit WindowsEventBaseBackend(event_base* evb);
  ~WindowsEventBaseBackend() override;

  event_base* getEventBase() override {
    return evb_;
  }

  int eb_event_base_loop(int flags) override;
  int eb_event_base_loopbreak() override;

  int eb_event_add(Event& event, const struct timeval* timeout) override;
  int eb_event_del(EventBaseBackendBase::Event& event) override;

  bool eb_event_active(Event& event, int res) override;

 private:
  event_base* evb_;
};

WindowsEventBaseBackend::WindowsEventBaseBackend() {
  evb_ = event_base_new();
}

WindowsEventBaseBackend::WindowsEventBaseBackend(event_base* evb) : evb_(evb) {
  if (UNLIKELY(evb_ == nullptr)) {
    LOG(ERROR) << "EventBase(): Pass nullptr as event base.";
    throw std::invalid_argument("EventBase(): event base cannot be nullptr");
  }
}

int WindowsEventBaseBackend::eb_event_base_loop(int flags) {
  return event_base_loop(evb_, flags);
}

int WindowsEventBaseBackend::eb_event_base_loopbreak() {
  return event_base_loopbreak(evb_);
}

int WindowsEventBaseBackend::eb_event_add(
    Event& event,
    const struct timeval* timeout) {
  return event_add(event.getEvent(), timeout);
}

int WindowsEventBaseBackend::eb_event_del(EventBaseBackendBase::Event& event) {
  return event_del(event.getEvent());
}

bool WindowsEventBaseBackend::eb_event_active(Event& event, int res) {
  event_active(event.getEvent(), res, 1);
  return true;
}

WindowsEventBaseBackend::~WindowsEventBaseBackend() {
  event_base_free(evb_);
}

static std::unique_ptr<folly::EventBaseBackendBase>
getWindowsEventBaseBackend() {
  auto config = event_config_new();
  event_config_set_flag(config, EVENT_BASE_FLAG_PRECISE_TIMER);
  auto evb = event_base_new_with_config(config);
  event_config_free(config);
  std::unique_ptr<folly::EventBaseBackendBase> backend =
      std::make_unique<WindowsEventBaseBackend>(evb);
  return backend;
}

#endif

QuicServer::EventBaseBackendDetails QuicServer::getEventBaseBackendDetails() {
  EventBaseBackendDetails ret;
#if _WIN32
  ret.factory = &getWindowsEventBaseBackend;
#else
  ret.factory = &folly::EventBase::getDefaultBackend;
#endif
  return ret;
}

} // namespace quic
