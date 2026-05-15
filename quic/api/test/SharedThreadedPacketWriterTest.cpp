/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/api/SharedThreadedPacketWriter.h>

#include <sys/socket.h>

#include <folly/io/async/AsyncUDPSocket.h>
#include <folly/io/async/ScopedEventBaseThread.h>
#include <folly/portability/GMock.h>
#include <folly/portability/GTest.h>
#include <folly/synchronization/Baton.h>

using namespace quic;
using ::testing::_;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;

// Minimal mock of folly::AsyncUDPSocket for STPW tests.
// Only writemGSO needs to be mocked — STPW calls no other socket methods
// (getNetworkSocket() is handled by setFD in SetUp).
class MockUDPSocket : public folly::AsyncUDPSocket {
 public:
  explicit MockUDPSocket(folly::EventBase* evb) : folly::AsyncUDPSocket(evb) {}
  MOCK_METHOD(
      int,
      writemGSO,
      (folly::Range<folly::SocketAddress const*>,
       const std::unique_ptr<folly::IOBuf>*,
       size_t,
       const folly::AsyncUDPSocket::WriteOptions*),
      (override));
};

namespace {

ConnectionId makeConnId(uint8_t byte) {
  return ConnectionId::createAndMaybeCrash({byte, 0, 0, 0});
}

BufPtr makeBuf(size_t size) {
  auto buf = folly::IOBuf::create(size);
  buf->append(size);
  return buf;
}

BufPtr makeBuf(size_t size, uint8_t fill) {
  auto buf = folly::IOBuf::create(size);
  buf->append(size);
  ::memset(buf->writableData(), fill, size);
  return buf;
}

} // namespace

class SharedThreadedPacketWriterTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_DGRAM, 0, fds_));
    sock_ = std::make_unique<NiceMock<MockUDPSocket>>(
        producerThread_.getEventBase());
    sock_->setFD(
        folly::NetworkSocket::fromFd(fds_[0]),
        folly::AsyncUDPSocket::FDOwnership::SHARED);
  }

  void TearDown() override {
    if (writer_) {
      // close() cancels flushCallback_ and must run on the producer EVB.
      onProducer([&] { writer_->close(); });
      // Destroy on drain thread so SocketWritableHandler::unregisterHandler()
      // runs on the correct EventBase.
      folly::Baton<> destroyed;
      drainThread_.getEventBase()->runInEventBaseThread(
          [w = std::move(writer_), &destroyed]() mutable {
            w.reset();
            destroyed.post();
          });
      destroyed.wait();
    }
    ::close(fds_[0]);
    ::close(fds_[1]);
    fds_[0] = fds_[1] = -1;
  }

  void makeWriter(
      size_t capacity = 64,
      size_t maxSegmentsPerMsg = 64,
      size_t maxMsgsPerCall = 64,
      size_t maxMsgsBeforeYield = 256) {
    writer_ = std::make_unique<SharedThreadedPacketWriter>(
        *sock_,
        producerThread_.getEventBase(),
        drainThread_.getEventBase(),
        capacity,
        maxSegmentsPerMsg,
        maxMsgsPerCall,
        maxMsgsBeforeYield);
  }

  // Run fn on the producer EventBase thread and block until it completes.
  template <typename Fn>
  void onProducer(Fn&& fn) {
    folly::Baton<> done;
    producerThread_.getEventBase()->runInEventBaseThread(
        [f = std::forward<Fn>(fn), &done]() mutable {
          f();
          done.post();
        });
    done.wait();
  }

  // Post a no-op to the drain EventBase and wait for it, ensuring all
  // previously-enqueued drain callbacks have completed.
  void awaitDrain() {
    folly::Baton<> idle;
    drainThread_.getEventBase()->runInEventBaseThread(
        [&idle] { idle.post(); });
    idle.wait();
  }

  // Member declaration order controls destructor order (C++ destroys in reverse
  // declaration order). drainThread_ must outlive writer_ so EventHandlers can
  // unregister from the drain EventBase in TearDown. sock_ must outlive writer_
  // since STPW holds a reference to it.
  folly::SocketAddress peer_{"127.0.0.1", 1234};
  int fds_[2]{-1, -1};
  folly::ScopedEventBaseThread producerThread_;
  folly::ScopedEventBaseThread drainThread_;
  std::unique_ptr<NiceMock<MockUDPSocket>> sock_;
  std::unique_ptr<SharedThreadedPacketWriter> writer_;
};

// Packets enqueued on producer thread reach writemGSO on drain thread.
TEST_F(SharedThreadedPacketWriterTest, NormalPath) {
  makeWriter();

  folly::Baton<> done;
  std::atomic<int> totalSegments{0};

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr* bufs,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            for (size_t i = 0; i < count; i++) {
              totalSegments.fetch_add(
                  static_cast<int>(bufs[i]->countChainElements()));
            }
            done.post();
            return static_cast<int>(count);
          }));

  auto connId = makeConnId(1);
  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    writer_->flush();
  });

  done.wait();
  awaitDrain();
  EXPECT_EQ(totalSegments.load(), 3);
}

// GSO grouping tests require Linux (UDP_SEGMENT / MSG_ERRQUEUE).
#ifdef FOLLY_HAVE_MSG_ERRQUEUE

// Same peer + same encoded size → one GSO mmsg entry with multiple segments.
TEST_F(SharedThreadedPacketWriterTest, GSOGrouping_SameAddrSameSize) {
  makeWriter();

  folly::Baton<> done;
  std::atomic<size_t> msgCount{0};
  std::atomic<size_t> segCount{0};

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr* bufs,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            msgCount.fetch_add(count);
            for (size_t i = 0; i < count; i++) {
              segCount.fetch_add(bufs[i]->countChainElements());
            }
            done.post();
            return static_cast<int>(count);
          }));

  auto connId = makeConnId(1);
  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    writer_->flush();
  });

  done.wait();
  awaitDrain();
  // 3 same-size same-addr packets should assemble into 1 GSO chain.
  EXPECT_EQ(msgCount.load(), 1u);
  EXPECT_EQ(segCount.load(), 3u);
}

#endif // FOLLY_HAVE_MSG_ERRQUEUE

// Different peer addresses produce separate mmsg entries.
TEST_F(SharedThreadedPacketWriterTest, GSOGrouping_DifferentAddr) {
  makeWriter();

  folly::Baton<> done;
  std::atomic<size_t> msgCount{0};

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr*,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            msgCount.fetch_add(count);
            done.post();
            return static_cast<int>(count);
          }));

  folly::SocketAddress peer2{"127.0.0.1", 5678};
  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, makeConnId(1)));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer2, makeConnId(2)));
    writer_->flush();
  });

  done.wait();
  awaitDrain();
  EXPECT_EQ(msgCount.load(), 2u);
}

#ifdef FOLLY_HAVE_MSG_ERRQUEUE

// A smaller last segment stays in the same GSO chain (valid GSO). The packet
// AFTER the smaller one starts a new chain because gso != newPrevSize.
TEST_F(SharedThreadedPacketWriterTest, GSOGrouping_TerminalSmallerSegment) {
  makeWriter();

  folly::Baton<> done;
  std::atomic<size_t> msgCount{0};
  std::atomic<size_t> segCount{0};

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr* bufs,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            msgCount.fetch_add(count);
            for (size_t i = 0; i < count; i++) {
              segCount.fetch_add(bufs[i]->countChainElements());
            }
            done.post();
            return static_cast<int>(count);
          }));

  auto connId = makeConnId(1);
  onProducer([&] {
    // {100,100,50} → one GSO chain (50 is valid smaller last segment).
    // The following 50 breaks the gso==prevSize invariant → new chain.
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(50), 50, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(50), 50, peer_, connId));
    writer_->flush();
  });

  done.wait();
  awaitDrain();
  // Chain 1: {100,100,50} gso=100; Chain 2: {50} gso=0
  EXPECT_EQ(msgCount.load(), 2u);
  EXPECT_EQ(segCount.load(), 4u);
}

#endif // FOLLY_HAVE_MSG_ERRQUEUE

// Queue full → write() returns false (backpressure).
TEST_F(SharedThreadedPacketWriterTest, Backpressure_QueueFull) {
  makeWriter(/*capacity=*/2);

  auto connId = makeConnId(1);
  bool third = true;
  // Do not flush — avoid drain-thread interaction in this test.
  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    third = writer_->write(makeBuf(100), 100, peer_, connId);
  });

  EXPECT_FALSE(third);
}

// EAGAIN on first writemGSO → EPOLLOUT fires → retryAndDrain → second call
// succeeds. The retry must deliver the same data to the same peer.
TEST_F(SharedThreadedPacketWriterTest, EAGAIN_RetryViaPollout) {
  makeWriter();

  folly::Baton<> retryDone;
  std::atomic<int> callCount{0};
  // Captured on drain thread; safe to read after retryDone + awaitDrain().
  size_t firstCount{0};
  size_t retryCount{0};
  std::string firstContent;
  std::string retryContent;
  folly::SocketAddress firstAddr;
  folly::SocketAddress retryAddr;

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*> addrs,
              const BufPtr* bufs,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            int n = callCount.fetch_add(1);
            if (n == 0) {
              firstCount = count;
              firstContent = std::string(
                  reinterpret_cast<const char*>(bufs[0]->data()),
                  bufs[0]->length());
              firstAddr = addrs[0];
              errno = EAGAIN;
              return -1;
            }
            retryCount = count;
            retryContent = std::string(
                reinterpret_cast<const char*>(bufs[0]->data()),
                bufs[0]->length());
            retryAddr = addrs[0];
            retryDone.post();
            return static_cast<int>(count);
          }));

  auto connId = makeConnId(1);
  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    writer_->flush();
  });

  retryDone.wait();
  awaitDrain();
  EXPECT_EQ(retryCount, firstCount);
  EXPECT_EQ(retryContent, firstContent);
  EXPECT_EQ(retryAddr, firstAddr);
}

// After close(), write() returns false immediately.
TEST_F(SharedThreadedPacketWriterTest, Closed_WritesRejected) {
  makeWriter();
  onProducer([&] { writer_->close(); });

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _)).Times(0);

  auto connId = makeConnId(1);
  bool result = true;
  // No flush — writer is closed, no drain expected.
  onProducer([&] {
    result = writer_->write(makeBuf(100), 100, peer_, connId);
  });
  EXPECT_FALSE(result);
}

// Packets enqueued with a deferred flush (pendingFlush_=true, not yet written
// to the eventfd) must still reach the drain thread when close() is called.
// close() cancels flushCallback_ and calls queue_.flush() directly so the
// drain thread is not stranded waiting for an eventfd that never fires.
TEST_F(SharedThreadedPacketWriterTest, Close_FlushesDeferredPackets) {
  makeWriter();

  folly::Baton<> done;
  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillOnce(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr*,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            done.post();
            return static_cast<int>(count);
          }));

  // write() + flush() + close() in one EVB turn: flushCallback_ is armed but
  // has not run yet when close() fires, exercising the cancel+flush path.
  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, makeConnId(1)));
    writer_->flush();
    writer_->close();
  });

  done.wait();
  awaitDrain();
}

#ifdef FOLLY_HAVE_MSG_ERRQUEUE

// maxSegmentsPerMsg_ cap: once a GSO chain reaches the limit the next segment
// starts a new mmsg entry.
TEST_F(SharedThreadedPacketWriterTest, GSOGrouping_MaxSegmentsPerMsg) {
  makeWriter(/*capacity=*/64, /*maxSegmentsPerMsg=*/2);

  folly::Baton<> done;
  std::atomic<size_t> msgCount{0};
  std::atomic<size_t> segCount{0};

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr* bufs,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            msgCount.fetch_add(count);
            for (size_t i = 0; i < count; i++) {
              segCount.fetch_add(bufs[i]->countChainElements());
            }
            done.post();
            return static_cast<int>(count);
          }));

  auto connId = makeConnId(1);
  onProducer([&] {
    // 3 same-size same-addr packets; cap is 2 segments → {100,100} + {100}.
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    writer_->flush();
  });

  done.wait();
  awaitDrain();
  EXPECT_EQ(msgCount.load(), 2u);
  EXPECT_EQ(segCount.load(), 3u);
}

// Packets from two different connections to the same peer with the same size
// are NOT grouped — cross-connection coalescing is excluded to keep connIds_
// as a flat per-slot vector instead of a per-slot vector<ConnectionId>.
TEST_F(SharedThreadedPacketWriterTest, GSOGrouping_CrossConnection) {
  makeWriter();

  folly::Baton<> done;
  std::atomic<size_t> msgCount{0};
  std::atomic<size_t> segCount{0};

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr* bufs,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            msgCount.fetch_add(count);
            for (size_t i = 0; i < count; i++) {
              segCount.fetch_add(bufs[i]->countChainElements());
            }
            if (msgCount.load() >= 2) {
              done.post();
            }
            return static_cast<int>(count);
          }));

  onProducer([&] {
    // Different connIds, same peer, same size → NOT grouped; connId mismatch
    // breaks the GSO chain so each packet becomes its own mmsg entry.
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, makeConnId(1)));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, makeConnId(2)));
    writer_->flush();
  });

  done.wait();
  awaitDrain();
  EXPECT_EQ(msgCount.load(), 2u);
  EXPECT_EQ(segCount.load(), 2u);
}

// A single connection sends 1200, 1200, 700, 700.
// Expected GSO grouping:
//   Slot 0: {1200, 1200, 700} = 3100 bytes  gso=1200  (700 is valid smaller terminal)
//   Slot 1: {700}             =  700 bytes  gso=0     (breaks chain: gso=1200 != prevSize=700)
// Verify GSO chain byte ordering. Packets are filled with distinct bytes
// (0x01, 0x02, 0x03, 0x04) so that the coalesce order is observable.
// Expected batching: slot0=[pkt1(1200,0x01), pkt2(1200,0x02), pkt3(700,0x03)]
// gso=1200; slot1=[pkt4(700,0x04)] gso=0.
TEST_F(SharedThreadedPacketWriterTest, GSOGrouping_1200_1200_700_700) {
  makeWriter();

  folly::Baton<> done;
  struct SlotInfo {
    std::vector<uint8_t> firstBytePerSeg; // first byte of each chain element
    std::vector<size_t> segLengths;
    int gso{0};
  };
  std::vector<SlotInfo> slots;

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr* bufs,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions* opts) -> int {
            for (size_t i = 0; i < count; i++) {
              SlotInfo s;
              s.gso = opts ? opts[i].gso : 0;
              for (const auto& seg : *bufs[i]) {
                s.firstBytePerSeg.push_back(seg.data()[0]);
                s.segLengths.push_back(seg.size());
              }
              slots.push_back(std::move(s));
            }
            done.post();
            return static_cast<int>(count);
          }));

  auto connId = makeConnId(1);
  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(1200, 0x01), 1200, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(1200, 0x02), 1200, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(700, 0x03), 700, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(700, 0x04), 700, peer_, connId));
    writer_->flush();
  });

  done.wait();
  awaitDrain();

  ASSERT_EQ(slots.size(), 2u);
  // Slot 0: [pkt1, pkt2, pkt3] in order, gso stride 1200.
  ASSERT_EQ(slots[0].firstBytePerSeg.size(), 3u);
  EXPECT_EQ(slots[0].firstBytePerSeg[0], 0x01);
  EXPECT_EQ(slots[0].firstBytePerSeg[1], 0x02);
  EXPECT_EQ(slots[0].firstBytePerSeg[2], 0x03);
  EXPECT_EQ(slots[0].segLengths[0], 1200u);
  EXPECT_EQ(slots[0].segLengths[1], 1200u);
  EXPECT_EQ(slots[0].segLengths[2], 700u);
  EXPECT_EQ(slots[0].gso, 1200);
  // Slot 1: pkt4 alone, no GSO needed.
  ASSERT_EQ(slots[1].firstBytePerSeg.size(), 1u);
  EXPECT_EQ(slots[1].firstBytePerSeg[0], 0x04);
  EXPECT_EQ(slots[1].segLengths[0], 700u);
  EXPECT_EQ(slots[1].gso, 0);
}

#endif // FOLLY_HAVE_MSG_ERRQUEUE

// assembleNextBatch fills at most maxMsgsPerCall_ slots. A second batch that
// uses fewer slots must pass bufs_.size() (not the preallocated array size) to
// writemGSO so stale entries from the first batch are excluded.
TEST_F(SharedThreadedPacketWriterTest, VariableBatchSizes) {
  // maxMsgsPerCall=2 forces the 3-packet queue to split across two batches.
  // maxMsgsBeforeYield=256 keeps both batches in the same drainQueue() call.
  makeWriter(
      /*capacity=*/64,
      /*maxSegmentsPerMsg=*/64,
      /*maxMsgsPerCall=*/2,
      /*maxMsgsBeforeYield=*/256);

  folly::Baton<> done;
  // Written only on the drain thread; safe to read after awaitDrain().
  std::vector<size_t> counts;

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr*,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            counts.push_back(count);
            if (counts.size() == 2) {
              done.post();
            }
            return static_cast<int>(count);
          }));

  // Three different peers → 3 separate msgs (no GSO grouping across peers).
  // maxMsgsPerCall=2 splits them into first batch of 2 and second batch of 1.
  onProducer([&] {
    EXPECT_TRUE(writer_->write(
        makeBuf(100), 100, folly::SocketAddress{"127.0.0.1", 1001}, makeConnId(1)));
    EXPECT_TRUE(writer_->write(
        makeBuf(100), 100, folly::SocketAddress{"127.0.0.1", 1002}, makeConnId(2)));
    EXPECT_TRUE(writer_->write(
        makeBuf(100), 100, folly::SocketAddress{"127.0.0.1", 1003}, makeConnId(3)));
    writer_->flush();
  });

  done.wait();
  awaitDrain();
  ASSERT_EQ(counts.size(), 2u);
  EXPECT_EQ(counts[0], 2u); // first batch: maxMsgsPerCall_ entries
  EXPECT_EQ(counts[1], 1u); // second batch: one remaining entry, not maxMsgsPerCall_
}

// ConnectionPacketWriter accumulates packetsSent / bytesSent in getResult().
TEST_F(SharedThreadedPacketWriterTest, ConnectionPacketWriter_AccumulatesResult) {
  makeWriter();

  folly::Baton<> done;
  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr*,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            done.post();
            return static_cast<int>(count);
          }));

  auto connId = makeConnId(1);
  ConnectionPacketWriter cpw(writer_.get(), connId);

  onProducer([&] {
    EXPECT_TRUE(*cpw.write(makeBuf(100), 100, peer_));
    EXPECT_TRUE(*cpw.write(makeBuf(200), 200, peer_));
    EXPECT_TRUE(*cpw.flush());
  });

  done.wait();
  awaitDrain();
  auto result = cpw.getResult();
  EXPECT_EQ(result.packetsSent, 2u);
  EXPECT_EQ(result.bytesSent, 300u);
}

// getResult() accumulates lifetime totals; callers compute per-cycle deltas by
// capturing a baseline before each write cycle. This verifies the delta is
// correct across two cycles (cycle 2 delta must be 2, not the lifetime total 3).
TEST_F(SharedThreadedPacketWriterTest, ConnectionPacketWriter_PerCycleDelta) {
  makeWriter();

  folly::Baton<> done1, done2;
  int call = 0;
  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr*,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            if (++call == 1) {
              done1.post();
            } else {
              done2.post();
            }
            return static_cast<int>(count);
          }));

  auto connId = makeConnId(1);
  ConnectionPacketWriter cpw(writer_.get(), connId);

  // Cycle 1: write 1 packet; delta should be 1.
  uint64_t base = cpw.getResult().packetsSent;
  onProducer([&] {
    EXPECT_TRUE(*cpw.write(makeBuf(100), 100, peer_));
    EXPECT_TRUE(*cpw.flush());
  });
  done1.wait();
  awaitDrain();
  EXPECT_EQ(cpw.getResult().packetsSent - base, 1u);

  // Cycle 2: write 2 packets. Delta must be 2, not 3 (lifetime total).
  base = cpw.getResult().packetsSent;
  onProducer([&] {
    EXPECT_TRUE(*cpw.write(makeBuf(100), 100, peer_));
    EXPECT_TRUE(*cpw.write(makeBuf(100), 100, peer_));
    EXPECT_TRUE(*cpw.flush());
  });
  done2.wait();
  awaitDrain();
  EXPECT_EQ(cpw.getResult().packetsSent - base, 2u);
  EXPECT_EQ(cpw.getResult().packetsSent, 3u); // lifetime total
}

// Non-EAGAIN writemGSO failure (fatal) → no retry, drainQueue returns.
TEST_F(SharedThreadedPacketWriterTest, FatalWriteError_NoRetry) {
  makeWriter();

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke(
          [](folly::Range<folly::SocketAddress const*>,
             const BufPtr*,
             size_t,
             const folly::AsyncUDPSocket::WriteOptions*) -> int {
            errno = EIO;
            return -1;
          }));

  auto connId = makeConnId(1);
  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    writer_->flush();
  });

  // Drain completes without crash; Times(1) enforces no retry attempt.
  awaitDrain();
}

// drainQueue() yields to the EventBase after maxMsgsBeforeYield msgs, then
// re-enters to drain the remainder.
TEST_F(SharedThreadedPacketWriterTest, YieldAndResumeDrain) {
  // maxMsgsPerCall=2 so each drainQueue iteration sends at most 2 msgs.
  // maxMsgsBeforeYield=2 so the yield triggers after every call.
  makeWriter(
      /*capacity=*/64,
      /*maxSegmentsPerMsg=*/64,
      /*maxMsgsPerCall=*/2,
      /*maxMsgsBeforeYield=*/2);

  folly::Baton<> done;
  std::atomic<size_t> totalSent{0};
  std::atomic<int> callCount{0};

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr*,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            callCount.fetch_add(1);
            if (totalSent.fetch_add(count) + count == 4) {
              done.post();
            }
            return static_cast<int>(count);
          }));

  // 4 different peers → 4 separate msgs (no GSO grouping across peers).
  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, {"127.0.0.1", 1001}, makeConnId(1)));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, {"127.0.0.1", 1002}, makeConnId(2)));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, {"127.0.0.1", 1003}, makeConnId(3)));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, {"127.0.0.1", 1004}, makeConnId(4)));
    writer_->flush();
  });

  done.wait();
  awaitDrain();
  EXPECT_EQ(totalSent.load(), 4u);
  // maxMsgsPerCall=2 forces >=2 writemGSO calls, confirming the yield path.
  EXPECT_GE(callCount.load(), 2);
}

// When the queue runs dry on the same assembleNextBatch() call that hits the
// yield threshold (hitEnd == true), no spurious drainQueue callback is
// scheduled. writemGSO is called exactly once.
TEST_F(SharedThreadedPacketWriterTest, YieldSuppressed_WhenQueueEmpty) {
  makeWriter(
      /*capacity=*/64,
      /*maxSegmentsPerMsg=*/64,
      /*maxMsgsPerCall=*/64,
      /*maxMsgsBeforeYield=*/1);

  folly::Baton<> done;

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .Times(1)
      .WillOnce(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr*,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            done.post();
            return static_cast<int>(count);
          }));

  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, makeConnId(1)));
    writer_->flush();
  });

  done.wait();
  // Extra awaitDrain() turn to catch any spurious drainQueue callback that
  // would violate Times(1) above.
  awaitDrain();
}

// Queue full → write() returns false; after drain drops below capacity/2,
// onResumeProducer fires on the producer EVB with the blocked connId.
TEST_F(SharedThreadedPacketWriterTest, Backpressure_ResumeProducer) {
  makeWriter(/*capacity=*/4);

  folly::Baton<> resumed;
  std::vector<ConnectionId> resumedIds;

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [](folly::Range<folly::SocketAddress const*>,
             const BufPtr*,
             size_t count,
             const folly::AsyncUDPSocket::WriteOptions*) -> int {
            return static_cast<int>(count);
          }));

  auto connId = makeConnId(1);
  onProducer([&] {
    writer_->setOnResumeProducer([&](const std::vector<ConnectionId>& ids) {
      resumedIds = ids;
      resumed.post();
    });
    // Fill queue completely (capacity=4).
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    // 5th write fails (queue full); register this connection as blocked.
    EXPECT_FALSE(writer_->write(makeBuf(100), 100, peer_, connId));
    writer_->registerBlocked(connId);
    writer_->flush();
  });

  resumed.wait();
  ASSERT_EQ(resumedIds.size(), 1u);
  EXPECT_EQ(resumedIds[0], connId);
}

// writemGSO returns 0 < ret < batch.size() (partial send). The unsent entries
// are retried; all packets must eventually be delivered with correct content.
TEST_F(SharedThreadedPacketWriterTest, PartialSend_RetryViaPollout) {
  makeWriter();

  folly::Baton<> retryDone;
  std::atomic<int> callCount{0};
  size_t totalDelivered{0};
  std::string skippedContent;
  std::string retryContent;

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr* bufs,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            int n = callCount.fetch_add(1);
            if (n == 0) {
              skippedContent = std::string(
                  reinterpret_cast<const char*>(bufs[1]->data()),
                  bufs[1]->length());
              totalDelivered += 1;
              return 1;
            }
            retryContent = std::string(
                reinterpret_cast<const char*>(bufs[0]->data()),
                bufs[0]->length());
            totalDelivered += static_cast<size_t>(count);
            retryDone.post();
            return static_cast<int>(count);
          }));

  // Two different peers produce two separate batch entries.
  onProducer([&] {
    EXPECT_TRUE(writer_->write(
        makeBuf(100), 100, folly::SocketAddress{"127.0.0.1", 1001}, makeConnId(1)));
    EXPECT_TRUE(writer_->write(
        makeBuf(100), 100, folly::SocketAddress{"127.0.0.1", 1002}, makeConnId(2)));
    writer_->flush();
  });

  retryDone.wait();
  awaitDrain();
  EXPECT_EQ(totalDelivered, 2u);
  EXPECT_EQ(retryContent, skippedContent);
}

// Fatal write error fires onFatalError on the producer EVB. If the connection
// is already gone by then, the callback handles "not found" gracefully.
TEST_F(SharedThreadedPacketWriterTest, ConnectionClosedWhileInQueue) {
  makeWriter();

  folly::Baton<> callbackRan;
  auto connId = makeConnId(1);
  bool seenExpectedId = false;

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillOnce(Invoke(
          [](folly::Range<folly::SocketAddress const*>,
             const BufPtr*,
             size_t,
             const folly::AsyncUDPSocket::WriteOptions*) -> int {
            errno = EIO;
            return -1;
          }));

  onProducer([&] {
    writer_->setOnFatalError([&](const ConnectionId& id, const QuicError&) {
      // Simulates a server worker that finds the connection already gone:
      // just record that the right connId was dispatched and drop it.
      seenExpectedId = (id == connId);
      callbackRan.post();
    });
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    writer_->flush();
  });

  callbackRan.wait();
  EXPECT_TRUE(seenExpectedId);
}

// close() called while the drain thread is inside writemGSO. The in-flight
// batch completes; subsequent writes on the producer are rejected.
TEST_F(SharedThreadedPacketWriterTest, ShutdownRace) {
  makeWriter();

  folly::Baton<> writemGSOEntered;
  folly::Baton<> resumeDrain;

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr*,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            writemGSOEntered.post();
            resumeDrain.wait(); // park until test thread signals
            return static_cast<int>(count);
          }));

  auto connId = makeConnId(1);
  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, connId));
    writer_->flush();
  });

  writemGSOEntered.wait(); // drain is now inside writemGSO

  // close() on the producer EVB while drain is mid-send.
  onProducer([&] { writer_->close(); });
  resumeDrain.post(); // let drain finish the in-flight send

  awaitDrain();

  // Writes after close() are rejected.
  bool afterClose = true;
  onProducer([&] {
    afterClose = writer_->write(makeBuf(100), 100, peer_, connId);
  });
  EXPECT_FALSE(afterClose);
}

// Two independent SharedThreadedPacketWriters sharing one drain EventBase both
// drain their queues correctly.
TEST_F(SharedThreadedPacketWriterTest, MultipleSocketsSharedDrainEvb) {
  int fds2[2]{-1, -1};
  ASSERT_EQ(0, ::socketpair(AF_UNIX, SOCK_DGRAM, 0, fds2));
  auto sock2 = std::make_unique<NiceMock<MockUDPSocket>>(
      producerThread_.getEventBase());
  sock2->setFD(
      folly::NetworkSocket::fromFd(fds2[0]),
      folly::AsyncUDPSocket::FDOwnership::SHARED);

  makeWriter();
  auto writer2 = std::make_unique<SharedThreadedPacketWriter>(
      *sock2,
      producerThread_.getEventBase(),
      drainThread_.getEventBase()); // shared drain EVB

  folly::Baton<> done1, done2;

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr*,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            done1.post();
            return static_cast<int>(count);
          }));

  EXPECT_CALL(*sock2, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [&](folly::Range<folly::SocketAddress const*>,
              const BufPtr*,
              size_t count,
              const folly::AsyncUDPSocket::WriteOptions*) -> int {
            done2.post();
            return static_cast<int>(count);
          }));

  onProducer([&] {
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, makeConnId(1)));
    writer_->flush();
    EXPECT_TRUE(writer2->write(makeBuf(100), 100, peer_, makeConnId(2)));
    writer2->flush();
  });

  done1.wait();
  done2.wait();

  // Tear down writer2: close on producer EVB, destroy on drain EVB.
  onProducer([&] { writer2->close(); });
  folly::Baton<> destroyed;
  drainThread_.getEventBase()->runInEventBaseThread(
      [w = std::move(writer2), &destroyed]() mutable {
        w.reset();
        destroyed.post();
      });
  destroyed.wait();
  ::close(fds2[0]);
  ::close(fds2[1]);
}

// A connection that filled the queue (registerBlocked) must not hang forever
// when a fatal write error occurs. The bug: when the queue has more items than
// maxMsgsPerCall, assembleNextBatch sets hitEnd=false, suppressing the
// wasEverFull_ low-watermark check. A fatal sendBatch() then returns early
// without scheduling resumeProducer, leaving blockedId hung indefinitely.
// Without the fix this test hangs indefinitely on resumed.wait().
TEST_F(SharedThreadedPacketWriterTest, BlockedConnection_WokenAfterFatalError) {
  // maxMsgsPerCall=2 with capacity=4: first batch assembles 2 items, hitEnd=false,
  // so the wasEverFull_ low-watermark path does NOT fire before the fatal error.
  makeWriter(/*capacity=*/4, /*maxSegmentsPerMsg=*/64, /*maxMsgsPerCall=*/2);

  folly::Baton<> resumed;
  auto blockedId = makeConnId(99);

  EXPECT_CALL(*sock_, writemGSO(_, _, _, _))
      .WillRepeatedly(Invoke(
          [](folly::Range<folly::SocketAddress const*>,
             const BufPtr*,
             size_t,
             const folly::AsyncUDPSocket::WriteOptions*) -> int {
            errno = EIO;
            return -1;
          }));

  onProducer([&] {
    writer_->setOnFatalError([](const ConnectionId&, const QuicError&) {});
    writer_->setOnResumeProducer([&](const std::vector<ConnectionId>&) {
      resumed.post();
    });
    // Fill the queue (4 items) then register blockedId as waiting for resume.
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, makeConnId(1)));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, makeConnId(2)));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, makeConnId(3)));
    EXPECT_TRUE(writer_->write(makeBuf(100), 100, peer_, makeConnId(4)));
    EXPECT_FALSE(writer_->write(makeBuf(100), 100, peer_, blockedId));
    writer_->registerBlocked(blockedId);
    writer_->flush();
  });

  resumed.wait(); // hangs forever without the fix
}
