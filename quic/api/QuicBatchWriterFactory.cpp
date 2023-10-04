/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/QuicBatchWriterFactory.h>

#if !FOLLY_MOBILE
#define USE_THREAD_LOCAL_BATCH_WRITER 1
#else
#define USE_THREAD_LOCAL_BATCH_WRITER 0
#endif

namespace {
#if USE_THREAD_LOCAL_BATCH_WRITER
class ThreadLocalBatchWriterCache : public folly::AsyncTimeout {
 private:
  ThreadLocalBatchWriterCache() = default;

  // we need to handle the case where the thread is being destroyed
  // while the EventBase has an outstanding timer
  struct Holder {
    Holder() = default;

    ~Holder() {
      if (ptr_) {
        ptr_->decRef();
      }
    }
    ThreadLocalBatchWriterCache* ptr_{nullptr};
  };

  void addRef() {
    ++count_;
  }

  void decRef() {
    if (--count_ == 0) {
      delete this;
    }
  }

 public:
  static ThreadLocalBatchWriterCache& getThreadLocalInstance() {
    static thread_local Holder sCache;
    if (!sCache.ptr_) {
      sCache.ptr_ = new ThreadLocalBatchWriterCache();
    }

    return *sCache.ptr_;
  }

  void timeoutExpired() noexcept override {
    timerActive_ = false;
    auto& instance = getThreadLocalInstance();
    if (instance.socket_ && instance.batchWriter_ &&
        !instance.batchWriter_->empty()) {
      // pass a default address - it is not being used by the writer
      instance.batchWriter_->write(*socket_.get(), folly::SocketAddress());
      instance.batchWriter_->reset();
    }
    decRef();
  }

  void enable(bool val) {
    if (enabled_ != val) {
      enabled_ = val;
      batchingMode_ = quic::QuicBatchingMode::BATCHING_MODE_NONE;
      batchWriter_.reset();
    }
  }

  quic::BatchWriter* FOLLY_NULLABLE getCachedWriter(
      quic::QuicBatchingMode mode,
      const std::chrono::microseconds& threadLocalDelay) {
    enabled_ = true;
    threadLocalDelay_ = threadLocalDelay;

    if (mode == batchingMode_) {
      return batchWriter_.release();
    }

    batchingMode_ = mode;
    batchWriter_.reset();

    return nullptr;
  }

  void setCachedWriter(quic::BatchWriter* writer) {
    if (enabled_) {
      auto* evb = writer->evb();

      if (evb && evb->getBackingEventBase() && !socket_) {
        auto fd = writer->getAndResetFd();
        if (fd >= 0) {
          socket_ = std::make_unique<quic::QuicAsyncUDPSocketWrapperImpl>(
              evb->getBackingEventBase());
          socket_->setFD(
              quic::toNetworkFdType(fd),
              quic::QuicAsyncUDPSocketWrapper::FDOwnership::OWNS);
        }
        attachTimeoutManager(evb->getBackingEventBase());
      }

      batchWriter_.reset(writer);

      // start the timer if not active
      if (evb && evb->getBackingEventBase() && socket_ && !timerActive_) {
        addRef();
        timerActive_ = true;
        evb->scheduleTimeoutHighRes(this, threadLocalDelay_);
      }
    } else {
      delete writer;
    }
  }

 private:
  std::atomic<uint32_t> count_{1};
  bool enabled_{false};
  bool timerActive_{false};
  std::chrono::microseconds threadLocalDelay_{1000};
  quic::QuicBatchingMode batchingMode_{
      quic::QuicBatchingMode::BATCHING_MODE_NONE};
  // this is just an  std::unique_ptr
  std::unique_ptr<quic::BatchWriter> batchWriter_;
  std::unique_ptr<quic::QuicAsyncUDPSocketWrapper> socket_;
};
#endif
} // namespace

namespace quic {

// BatchWriterDeleter
void BatchWriterDeleter::operator()(BatchWriter* batchWriter) {
#if USE_THREAD_LOCAL_BATCH_WRITER
  ThreadLocalBatchWriterCache::getThreadLocalInstance().setCachedWriter(
      batchWriter);
#else
  delete batchWriter;
#endif
}

BatchWriterPtr makeGsoBatchWriter(uint32_t batchSize) {
  return BatchWriterPtr(new GSOPacketBatchWriter(batchSize));
}

BatchWriterPtr makeGsoInPlaceBatchWriter(
    uint32_t batchSize,
    QuicConnectionStateBase& conn) {
  return BatchWriterPtr(new GSOInplacePacketBatchWriter(conn, batchSize));
}

BatchWriterPtr makeSendmmsgGsoBatchWriter(uint32_t batchSize) {
  return BatchWriterPtr(new SendmmsgGSOPacketBatchWriter(batchSize));
}

BatchWriterPtr BatchWriterFactory::makeBatchWriter(
    const quic::QuicBatchingMode& batchingMode,
    uint32_t batchSize,
    bool useThreadLocal,
    const std::chrono::microseconds& threadLocalDelay,
    DataPathType dataPathType,
    QuicConnectionStateBase& conn,
    bool gsoSupported) {
#if USE_THREAD_LOCAL_BATCH_WRITER
  if (useThreadLocal &&
      (batchingMode == quic::QuicBatchingMode::BATCHING_MODE_SENDMMSG_GSO) &&
      gsoSupported) {
    BatchWriterPtr ret(
        ThreadLocalBatchWriterCache::getThreadLocalInstance().getCachedWriter(
            batchingMode, threadLocalDelay));

    if (ret) {
      return ret;
    }
  } else {
    ThreadLocalBatchWriterCache::getThreadLocalInstance().enable(false);
  }
#else
  (void)useThreadLocal;
  (void)threadLocalDelay;
#endif

  return makeBatchWriterHelper(
      batchingMode, batchSize, dataPathType, conn, gsoSupported);
}

} // namespace quic
