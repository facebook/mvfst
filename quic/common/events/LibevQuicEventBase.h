/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/events/QuicEventBase.h>
#include <quic/common/events/QuicTimer.h>

#include <ev.h>
#include <chrono>
#include <memory>
#include <thread>

#if __has_include(<sys/timerfd.h>)
#include <sys/timerfd.h>
extern "C" __attribute__((__weak__)) int timerfd_create(int clockid, int flags);

extern "C" __attribute__((__weak__)) int timerfd_settime(
    int fd,
    int flags,
    const struct itimerspec* new_value,
    struct itimerspec* _Nullable old_value);

#define HAS_TIMERFD 1
#endif

#include <folly/GLog.h>
#include <folly/IntrusiveList.h>

namespace quic {
/*
 * This is a partial implementation of a QuicEventBase that uses libev.
 * (It is copied from the previous interface in
 * quic/common/QuicLibevEventBase.h)
 */
class LibevQuicEventBase
    : public QuicEventBase,
      public QuicTimer,
      public std::enable_shared_from_this<LibevQuicEventBase> {
 public:
  class EvLoopWeak {
   public:
    // Returns nullptr if the loop has been destroyed.
    virtual struct ev_loop* get() = 0;

    virtual ~EvLoopWeak() = default;
  };
  explicit LibevQuicEventBase(std::unique_ptr<EvLoopWeak> loop);
  ~LibevQuicEventBase() override;

  void runInLoop(
      QuicEventBaseLoopCallback* callback,
      bool thisIteration = false) override;

  void runInLoop(folly::Function<void()> cb, bool thisIteration = false)
      override;

  bool isInEventBaseThread() const override;

  // QuicEventBase
  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::milliseconds timeout) override;

  // QuicEventBase
  bool scheduleTimeoutHighRes(
      QuicTimerCallback* /*callback*/,
      std::chrono::microseconds /*timeout*/) override;

  // QuicTimer
  void scheduleTimeout(
      QuicTimerCallback* callback,
      std::chrono::microseconds timeout) override;

  bool loop() override {
    return ev_run(ev_loop_, EVRUN_NOWAIT);
  }

  bool loopIgnoreKeepAlive() override {
    return false;
  }

  void runInEventBaseThread(folly::Function<void()> /*fn*/) noexcept override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  void runInEventBaseThreadAndWait(
      folly::Function<void()> /*fn*/) noexcept override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  void runImmediatelyOrRunInEventBaseThreadAndWait(
      folly::Function<void()> /*fn*/) noexcept override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  void runImmediatelyOrRunInEventBaseThread(
      folly::Function<void()> /*fn*/) noexcept override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  void runAfterDelay(folly::Function<void()> /*cb*/, uint32_t /*milliseconds*/)
      override {
    LOG(FATAL) << __func__ << " not supported in LibevQuicEventBase";
  }

  bool loopOnce(int /*flags*/) override {
    return ev_run(ev_loop_, EVRUN_ONCE | EVRUN_NOWAIT);
  }

  void loopForever() override {
    ev_run(ev_loop_, 0);
  }

  void terminateLoopSoon() override {
    ev_break(ev_loop_, EVBREAK_ALL);
  }

  [[nodiscard]] std::chrono::milliseconds getTimerTickInterval()
      const override {
    return std::chrono::milliseconds(1);
  }

  [[nodiscard]] std::chrono::microseconds getTickInterval() const override {
    return std::chrono::milliseconds(1);
  }

  // MUST be called before any timers are scheduled.
  void useTimerFd() {
#if defined(HAS_TIMERFD)
    useTimerFd_ = true;
#endif
  }

  void prioritizeTimers() {
    prioritizeTimers_ = true;
  }

  struct ev_loop* getLibevLoop() {
    return ev_loop_;
  }

  EvLoopWeak* getLoopWeak() {
    return loopWeak_.get();
  }

  // This is public so the libev callback can access it
  void checkCallbacks();

  // This is public so the libev callback can access it
  class TimerCallbackWrapper : public QuicTimerCallback::TimerCallbackImpl {
   public:
    explicit TimerCallbackWrapper(
        QuicTimerCallback* callback,
        struct ev_loop* ev_loop)
        : callback_(callback), ev_loop_(ev_loop) {}

    friend class LibevQuicEventBase;

    void timeoutExpired() noexcept {
      callback_->timeoutExpired();
    }

    void callbackCanceled() noexcept {
      callback_->callbackCanceled();
    }

    void cancelImpl() noexcept override {
      ev_timer_stop(ev_loop_, &ev_timer_);
    }

    [[nodiscard]] bool isScheduledImpl() const noexcept override {
      return ev_is_active(&ev_timer_) || ev_is_pending(&ev_timer_);
    }

    [[nodiscard]] std::chrono::milliseconds getTimeRemainingImpl()
        const noexcept override {
      LOG(FATAL) << __func__ << " not implemented in LibevQuicEventBase";
    }

   private:
    QuicTimerCallback* callback_;
    struct ev_loop* ev_loop_;
    ev_timer ev_timer_;
  };

  class TimerCallbackWrapperTimerFD
      : public QuicTimerCallback::TimerCallbackImpl {
   public:
    TimerCallbackWrapperTimerFD(
        QuicTimerCallback* callback,
        struct ev_loop* ev_loop,
        bool prioritizeTimers)
        : callback_(callback), ev_loop_(ev_loop) {
#if defined(HAS_TIMERFD)
      ev_io_watcher_.fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
      if (ev_io_watcher_.fd == -1) {
        LOG(FATAL) << "Failed to create timerfd";
      }
      ev_io_init(
          &ev_io_watcher_,
          [](struct ev_loop* loop, ev_io* w, int) {
            uint64_t expirations;
            read(w->fd, &expirations, sizeof(expirations));
            auto wrapper = static_cast<TimerCallbackWrapperTimerFD*>(w->data);
            ev_io_stop(loop, w);
            wrapper->timeoutExpired();
          },
          ev_io_watcher_.fd,
          EV_READ);
      if (prioritizeTimers) {
        ev_set_priority(&ev_io_watcher_, EV_MAXPRI);
      }
#else
      LOG(FATAL) << "TimerFD not supported on this platform";
#endif
    }

    ~TimerCallbackWrapperTimerFD() override {
#if defined(HAS_TIMERFD)
      cancelImpl();
      close(ev_io_watcher_.fd);
#endif
    }

    friend class LibevQuicEventBase;

    void timeoutExpired() noexcept {
      callback_->timeoutExpired();
    }

    void callbackCanceled() noexcept {
      callback_->callbackCanceled();
    }

    void cancelImpl() noexcept override {
#if defined(HAS_TIMERFD)
      struct itimerspec new_value = {};
      if (timerfd_settime(ev_io_watcher_.fd, 0, &new_value, nullptr) == -1) {
        LOG(FATAL) << "Failed to set timerfd time";
      }
      ev_io_stop(ev_loop_, &ev_io_watcher_);
#endif
    }

    [[nodiscard]] bool isScheduledImpl() const noexcept override {
      return ev_is_active(&ev_io_watcher_) || ev_is_pending(&ev_io_watcher_);
    }

    [[nodiscard]] std::chrono::milliseconds getTimeRemainingImpl()
        const noexcept override {
      LOG(FATAL) << __func__ << " not implemented in LibevQuicEventBase";
    }

   private:
    QuicTimerCallback* callback_;
    [[maybe_unused]] struct ev_loop* ev_loop_;
    [[maybe_unused]] ev_io ev_io_watcher_;
  };

 private:
  class LoopCallbackWrapper
      : public QuicEventBaseLoopCallback::LoopCallbackImpl {
   public:
    explicit LoopCallbackWrapper(QuicEventBaseLoopCallback* callback)
        : callback_(callback) {}

    ~LoopCallbackWrapper() override {
      listHook_.unlink();
    }

    friend class LibevQuicEventBase;

    void runLoopCallback() noexcept {
      listHook_.unlink();
      callback_->runLoopCallback();
    }

    void cancelImpl() noexcept override {
      // Removing the callback from the instrusive list is effectively
      // cancelling it.
      listHook_.unlink();
    }
    [[nodiscard]] bool isScheduledImpl() const noexcept override {
      return listHook_.is_linked();
    }

   private:
    QuicEventBaseLoopCallback* callback_;
    folly::IntrusiveListHook listHook_;
  };

  class FunctionLoopCallback : public quic::QuicEventBaseLoopCallback {
   public:
    explicit FunctionLoopCallback(folly::Function<void()>&& func)
        : func_(std::move(func)) {}

    void runLoopCallback() noexcept override {
      func_();
      delete this;
    }

    friend class LibevQuicEventBase;

   private:
    folly::Function<void()> func_;
    folly::IntrusiveListHook listHook_;
  };

  void scheduleLibevTimeoutImpl(
      QuicTimerCallback* timerCallback,
      std::chrono::microseconds timeout);

  void scheduleTimerFDTimeoutImpl(
      QuicTimerCallback* timerCallback,
      std::chrono::microseconds timeout);

  struct ev_loop* ev_loop_{EV_DEFAULT};
  std::unique_ptr<EvLoopWeak> loopWeak_;

  folly::IntrusiveList<LoopCallbackWrapper, &LoopCallbackWrapper::listHook_>
      loopCallbackWrappers_;

  // This will be null most of the time, but point to the current list of
  // callbacks if we are in the middle of running loop callbacks, such that
  // runInLoop(..., true) will always run in the current loop
  // iteration.
  folly::IntrusiveList<LoopCallbackWrapper, &LoopCallbackWrapper::listHook_>*
      runOnceCallbackWrappers_{nullptr};

  folly::IntrusiveList<FunctionLoopCallback, &FunctionLoopCallback::listHook_>
      functionLoopCallbacks_;

  // ev_prepare is supposed to run before the loop goes to sleep.
  // We're using it to execute delayed work given to us via runInLoop.
  ev_prepare prepareWatcher_;
  std::atomic<std::thread::id> loopThreadId_;
  bool useTimerFd_{false};
  bool prioritizeTimers_{false};
};
} // namespace quic
