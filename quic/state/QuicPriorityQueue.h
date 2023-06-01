/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/container/F14Map.h>
#include <glog/logging.h>
#include <set>

#include <quic/codec/Types.h>

namespace quic {

constexpr uint8_t kDefaultPriorityLevels = kDefaultMaxPriority + 1;
constexpr uint8_t kDefaultPriorityLevelsSize = 2 * kDefaultPriorityLevels;

using OrderId = uint64_t;

struct OrderedStream {
  StreamId streamId;
  OrderId orderId;
  OrderedStream(StreamId s, OrderId o) : streamId(s), orderId(o) {}
};

struct ordered_stream_cmp {
  bool operator()(OrderedStream lhs, OrderedStream rhs) const {
    return (lhs.orderId == rhs.orderId) ? lhs.streamId < rhs.streamId
                                        : lhs.orderId < rhs.orderId;
  }
};

using OrderedStreamSet = std::set<OrderedStream, ordered_stream_cmp>;

/**
 * Priority is expressed as a level [0,7] and an incremental flag.
 */
struct Priority {
  uint8_t level : 3;
  bool incremental : 1;
  OrderId orderId : 58;

  Priority(uint8_t l, bool i, OrderId o = 0)
      : level(l), incremental(i), orderId(o) {}

  bool operator==(Priority other) const noexcept {
    return level == other.level && incremental == other.incremental &&
        orderId == other.orderId;
  }
};

extern const Priority kDefaultPriority;

/**
 * Priority queue for Quic streams.  It represents each level/incremental bucket
 * as an entry in a vector.  Each entry holds a set of streams (sorted by
 * stream ID, ascending).  There is also a map of all streams currently in the
 * queue, mapping from ID -> bucket index.  The interface is almost identical
 * to std::set (insert, erase, count, clear), except that insert takes an
 * optional priority parameter.
 */
struct PriorityQueue {
  struct Level {
    class Iterator {
     protected:
      const Level& level;

     public:
      explicit Iterator(const Level& inLevel, uint64_t maxNexts)
          : level(inLevel),
            maxNextsPerStream(maxNexts),
            nextStreamIt(level.streams.end()) {}
      virtual ~Iterator() = default;
      virtual void begin() const = 0;
      virtual bool end() const = 0;
      virtual StreamId current() const {
        return nextStreamIt->streamId;
      }
      virtual void next(bool force = false) = 0;
      virtual void override(OrderedStreamSet::const_iterator it) {
        nextStreamIt = it;
      }
      mutable uint64_t nextsSoFar{0};
      uint64_t maxNextsPerStream{1};
      mutable OrderedStreamSet::const_iterator nextStreamIt;
    };

    class IncrementalIterator : public Iterator {
     private:
      mutable OrderedStreamSet::const_iterator startStreamIt;

     public:
      explicit IncrementalIterator(const Level& inLevel, uint64_t maxNexts)
          : Iterator(inLevel, maxNexts), startStreamIt(level.streams.end()) {}
      void begin() const override {
        if (nextStreamIt == level.streams.end()) {
          nextStreamIt = level.streams.begin();
        }
        startStreamIt = nextStreamIt;
      }
      bool end() const override {
        return nextStreamIt == startStreamIt;
      }
      // force will ignore the max nexts and always moves to the next stream.
      void next(bool force) override {
        CHECK(!level.empty());
        if (!force && ++nextsSoFar < maxNextsPerStream) {
          return;
        }
        nextStreamIt++;
        if (nextStreamIt == level.streams.end()) {
          nextStreamIt = level.streams.begin();
        }
        nextsSoFar = 0;
      }
    };

    class SequentialIterator : public Iterator {
     public:
      explicit SequentialIterator(const Level& inLevel, uint64_t maxNexts)
          : Iterator(inLevel, maxNexts) {}
      void begin() const override {
        nextStreamIt = level.streams.begin();
      }
      bool end() const override {
        return nextStreamIt == level.streams.end();
      }
      void next(bool) override {
        CHECK(!level.empty());
        nextStreamIt++;
      }
    };

    OrderedStreamSet streams;
    bool incremental{false};
    std::unique_ptr<Iterator> iterator;
    FOLLY_NODISCARD bool empty() const {
      return streams.empty();
    }

    FOLLY_NODISCARD OrderedStream getOrderedStream(StreamId id) const {
      auto it = streamToOrderId.find(id);
      if (it == streamToOrderId.end()) {
        return OrderedStream(id, 0);
      }
      return OrderedStream(id, it->second);
    }

    bool insert(StreamId streamId, OrderId orderId) {
      if (orderId > 0) {
        streamToOrderId[streamId] = orderId;
      }
      return streams.insert(OrderedStream(streamId, orderId)).second;
    }

    OrderedStreamSet::const_iterator erase(
        OrderedStreamSet::const_iterator it) {
      streamToOrderId.erase(it->streamId);
      return streams.erase(it);
    }

   private:
    folly::F14FastMap<StreamId, OrderId> streamToOrderId;
  };
  std::vector<Level> levels;
  using LevelItr = decltype(levels)::const_iterator;
  // This controls how many times next() needs to be called before moving
  // onto the next stream.
  uint64_t maxNextsPerStream{1};

  void setMaxNextsPerStream(uint64_t maxNexts) {
    maxNextsPerStream = maxNexts;
    for (auto& l : levels) {
      l.iterator->maxNextsPerStream = maxNexts;
    }
  }

  PriorityQueue() : levels(kDefaultPriorityLevelsSize) {
    for (size_t index = 0; index < levels.size(); index++) {
      if (index % 2 == 1) {
        levels[index].incremental = true;
        levels[index].iterator = std::make_unique<Level::IncrementalIterator>(
            levels[index], maxNextsPerStream);
      } else {
        levels[index].iterator = std::make_unique<Level::SequentialIterator>(
            levels[index], maxNextsPerStream);
      }
    }
  }

  static uint8_t priority2index(Priority pri) {
    uint8_t index = pri.level * 2 + uint8_t(pri.incremental);
    DCHECK_LT(index, kDefaultPriorityLevelsSize)
        << "Logic error: level=" << pri.level
        << " incremental=" << pri.incremental;
    return index;
  }

  /**
   * Update stream priority if the stream already exist in the PriorityQueue
   *
   * This is a no-op if the stream doesn't exist, or its priority is the same as
   * the input.
   */
  void updateIfExist(StreamId id, Priority priority) {
    auto iter = writableStreamsToLevel_.find(id);
    if (iter != writableStreamsToLevel_.end()) {
      updateExistingStreamPriority(iter, priority);
    }
  }

  void insertOrUpdate(StreamId id, Priority pri) {
    auto it = writableStreamsToLevel_.find(id);
    auto index = priority2index(pri);
    if (it != writableStreamsToLevel_.end()) {
      updateExistingStreamPriority(it, pri);
    } else {
      writableStreamsToLevel_.emplace(id, index);
      auto res = levels[index].insert(id, pri.orderId);
      DCHECK(res) << "PriorityQueue inconsistent: stream=" << id
                  << " already at level=" << index;
    }
  }

  void erase(StreamId id) {
    auto it = writableStreamsToLevel_.find(id);
    if (it != writableStreamsToLevel_.end()) {
      eraseFromLevel(it->second, it->first);
      writableStreamsToLevel_.erase(it);
    }
  }

  // Only used for testing
  void clear() {
    writableStreamsToLevel_.clear();
    for (auto& level : levels) {
      level.streams.clear();
      level.iterator->nextStreamIt = level.streams.end();
    }
  }

  FOLLY_NODISCARD size_t count(StreamId id) const {
    return writableStreamsToLevel_.count(id);
  }

  FOLLY_NODISCARD bool empty() const {
    return writableStreamsToLevel_.empty();
  }

  // Testing helper to override scheduling state
  void setNextScheduledStream(StreamId id) {
    auto it = writableStreamsToLevel_.find(id);
    CHECK(it != writableStreamsToLevel_.end());
    auto& level = levels[it->second];
    const auto& stream = level.getOrderedStream(id);
    auto streamIt = level.streams.find(stream);
    CHECK(streamIt != level.streams.end());
    level.iterator->override(streamIt);
  }

  // Only used for testing
  void prepareIterator(Priority pri) {
    auto& level = levels[priority2index(pri)];
    level.iterator->begin();
  }

  // Only used for testing
  FOLLY_NODISCARD StreamId getNextScheduledStream(Priority pri) const {
    auto& level = levels[priority2index(pri)];
    if (!level.incremental ||
        level.iterator->nextStreamIt == level.streams.end()) {
      CHECK(!level.streams.empty());
      return level.streams.begin()->streamId;
    }
    return level.iterator->nextStreamIt->streamId;
  }

  FOLLY_NODISCARD StreamId getNextScheduledStream() const {
    const auto& levelIter =
        std::find_if(levels.cbegin(), levels.cend(), [&](const auto& level) {
          return !level.empty();
        });
    // The expectation is that calling this function on an empty queue is
    // a bug.
    CHECK(levelIter != levels.cend());
    levelIter->iterator->begin();
    return levelIter->iterator->current();
  }

 private:
  folly::F14FastMap<StreamId, uint8_t> writableStreamsToLevel_;
  using WSIterator = decltype(writableStreamsToLevel_)::iterator;

  void eraseFromLevel(uint8_t levelIndex, StreamId id) {
    auto& level = levels[levelIndex];
    const auto& stream = level.getOrderedStream(id);
    auto streamIt = level.streams.find(stream);
    if (streamIt == level.streams.end()) {
      LOG(DFATAL) << "Stream=" << levelIndex
                  << " not found in PriorityQueue level=" << id;
      return;
    }
    if (streamIt == level.iterator->nextStreamIt) {
      level.iterator->nextStreamIt = level.streams.erase(streamIt);
      level.iterator->nextsSoFar = 0;
    } else {
      level.streams.erase(streamIt);
    }
  }

  void updateExistingStreamPriority(WSIterator it, Priority pri) {
    CHECK(it != writableStreamsToLevel_.end());
    auto index = priority2index(pri);
    if (it->second == index) {
      // same priority, doesn't need changing
      return;
    }
    VLOG(4) << "Updating priority of stream=" << it->first << " from "
            << it->second << " to " << index;
    eraseFromLevel(it->second, it->first);
    it->second = index;
    auto res = levels[index].insert(it->first, pri.orderId);
    DCHECK(res) << "PriorityQueue inconsistent: stream=" << it->first
                << " already at level=" << index;
  }
};

} // namespace quic
