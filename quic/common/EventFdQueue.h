/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fcntl.h>
#include <unistd.h>

#if __has_include(<sys/eventfd.h>)
#include <sys/eventfd.h>
#define QUIC_HAS_EVENTFD 1
#else
#define QUIC_HAS_EVENTFD 0
#endif

#include <folly/Function.h>
#include <folly/ProducerConsumerQueue.h>
#include <folly/io/async/EventBase.h>
#include <folly/io/async/EventHandler.h>

#include <glog/logging.h>

namespace quic {

/**
 * SPSC queue with asynchronous wakeup.
 *
 * The producer calls enqueue() from one thread and flush() once per batch.
 * The consumer is driven by a folly::EventBase; setOnReadable() registers
 * the callback fired when items are ready.
 *
 * Wakeup uses eventfd on Linux (EFD_NONBLOCK; counter semantics coalesce
 * multiple flush() calls into one wakeup) and a non-blocking self-pipe on
 * platforms without eventfd (e.g. macOS).
 */
template <typename T>
class EventFdQueue {
 public:
  EventFdQueue(folly::EventBase* consumerEvb, size_t capacity)
      // ProducerConsumerQueue with size N holds N-1 items; add 1 so the
      // external-facing capacity is exact.
      : queue_(static_cast<uint32_t>(capacity + 1)) {
    initNotifyFds();
    handler_ =
        std::make_unique<DrainHandler>(this, consumerEvb, readFd());
  }

  // Begin consuming. Must be called from the consumer EventBase thread.
  // Calling registerHandler() (which calls event_add/kevent) from an off-thread
  // is not safe on macOS kqueue — the filter may not be visible to the waiting
  // kevent() call. Modelled on folly::NotificationQueue::Consumer::startConsuming().
  void startConsuming() {
    handler_->registerHandler(folly::EventHandler::READ | folly::EventHandler::PERSIST);
  }

  ~EventFdQueue() {
    handler_->unregisterHandler();
#if QUIC_HAS_EVENTFD
    ::close(eventfd_);
#else
    ::close(pipeFds_[0]);
    ::close(pipeFds_[1]);
#endif
  }

  // Producer thread. Returns false if queue is full.
  bool enqueue(T item) {
    if (!queue_.write(std::move(item))) {
      return false;
    }
    pendingFlush_ = true;
    return true;
  }

  // Producer thread. Signal the consumer once if anything was enqueued since
  // last flush. Multiple enqueues coalesce into one wakeup.
  void flush() {
    if (!pendingFlush_) {
      return;
    }
    pendingFlush_ = false;
#if QUIC_HAS_EVENTFD
    uint64_t one = 1;
    auto ret = ::write(eventfd_, &one, sizeof(one));
    PCHECK(ret == (ssize_t)sizeof(one) || errno == EAGAIN || errno == EWOULDBLOCK);
#else
    char one = 1;
    auto ret = ::write(pipeFds_[1], &one, 1);
    PCHECK(ret == 1 || errno == EAGAIN || errno == EWOULDBLOCK);
#endif
  }

  // Consumer setup. Must be called before events start firing.
  void setOnReadable(folly::Function<void()> cb) {
    onReadable_ = std::move(cb);
  }

  // Consumer thread. Returns false if queue is empty.
  bool dequeue(T& out) {
    return queue_.read(out);
  }

  // Approximate number of items currently in the queue. Safe to call from any
  // thread; uses the same relaxed loads as folly::ProducerConsumerQueue.
  size_t sizeGuess() const {
    return queue_.sizeGuess();
  }

 private:
  void initNotifyFds() {
#if QUIC_HAS_EVENTFD
    eventfd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    PCHECK(eventfd_ >= 0) << "eventfd() failed";
#else
    PCHECK(::pipe(pipeFds_) == 0) << "pipe() failed";
    PCHECK(::fcntl(pipeFds_[0], F_SETFL, O_NONBLOCK) != -1);
    PCHECK(::fcntl(pipeFds_[1], F_SETFL, O_NONBLOCK) != -1);
#endif
  }

  int readFd() const {
#if QUIC_HAS_EVENTFD
    return eventfd_;
#else
    return pipeFds_[0];
#endif
  }

  // Drain the wakeup fd so it rearms for the next flush().
  void drainWakeupFd() {
#if QUIC_HAS_EVENTFD
    uint64_t val;
    while (::read(eventfd_, &val, sizeof(val)) > 0) {
    }
#else
    char buf[64];
    while (::read(pipeFds_[0], buf, sizeof(buf)) > 0) {
    }
#endif
  }

  class DrainHandler : public folly::EventHandler {
   public:
    DrainHandler(EventFdQueue* q, folly::EventBase* evb, int fd)
        : folly::EventHandler(evb, folly::NetworkSocket::fromFd(fd)), q_(q) {}

    void handlerReady(uint16_t /*events*/) noexcept override {
      q_->drainWakeupFd();
      if (q_->onReadable_) {
        q_->onReadable_();
      }
    }

   private:
    EventFdQueue* q_;
  };

  folly::ProducerConsumerQueue<T> queue_;
#if QUIC_HAS_EVENTFD
  int eventfd_{-1};
#else
  int pipeFds_[2]{-1, -1};
#endif
  bool pendingFlush_{false};
  std::unique_ptr<DrainHandler> handler_;
  folly::Function<void()> onReadable_;
};

} // namespace quic
