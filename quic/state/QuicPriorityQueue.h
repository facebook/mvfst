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

/**
 * Priority is expressed as a level [0,7] and an incremental flag.
 */
struct Priority {
  uint8_t level : 3;
  bool incremental : 1;

  Priority(uint8_t l, bool i) : level(l), incremental(i) {}

  bool operator==(Priority other) const noexcept {
    return level == other.level && incremental == other.incremental;
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
    std::set<StreamId> streams;
    mutable decltype(streams)::const_iterator next{streams.end()};
    bool incremental{false};
  };
  std::vector<Level> levels;

  PriorityQueue() {
    levels.resize(kDefaultPriorityLevels * 2);
    for (size_t index = 1; index < levels.size(); index += 2) {
      levels[index].incremental = true;
    }
  }

  static size_t priority2index(Priority pri, size_t max) {
    auto index = pri.level * 2 + uint8_t(pri.incremental);
    DCHECK_LT(index, max) << "Logic error: level=" << pri.level
                          << " incremental=" << pri.incremental;
    return index;
  }

  /**
   * Update stream priority if the stream already exist in the PriorityQueue
   *
   * This is a no-op if the stream doesn't exist, or its priority is the same as
   * the input.
   */
  void updateIfExist(StreamId id, Priority priority = kDefaultPriority) {
    auto iter = writableStreams.find(id);
    if (iter == writableStreams.end()) {
      return;
    }
    auto index = priority2index(priority, levels.size());
    if (iter->second == index) {
      // no need to update
      return;
    }
    eraseFromLevel(iter->second, iter->first);
    iter->second = index;
    auto res = levels[index].streams.insert(id);
    DCHECK(res.second) << "PriorityQueue inconsistentent: stream=" << id
                       << " already at level=" << index;
  }

  void insertOrUpdate(StreamId id, Priority pri = kDefaultPriority) {
    auto it = writableStreams.find(id);
    auto index = priority2index(pri, levels.size());
    if (it != writableStreams.end()) {
      if (it->second == index) {
        // No op, this stream is already inserted at the correct priority level
        return;
      }
      VLOG(4) << "Updating priority of stream=" << id << " from " << it->second
              << " to " << index;
      // Meh, too hard.  Just erase it and start over.
      eraseFromLevel(it->second, it->first);
      it->second = index;
    } else {
      writableStreams.emplace(id, index);
    }
    auto res = levels[index].streams.insert(id);
    DCHECK(res.second) << "PriorityQueue inconsistentent: stream=" << id
                       << " already at level=" << index;
  }

  void erase(StreamId id) {
    auto it = find(id);
    erase(it);
  }

  // Only used for testing
  void clear() {
    writableStreams.clear();
    for (auto& level : levels) {
      level.streams.clear();
      level.next = level.streams.end();
    }
  }

  FOLLY_NODISCARD size_t count(StreamId id) const {
    return writableStreams.count(id);
  }

  FOLLY_NODISCARD bool empty() const {
    return writableStreams.empty();
  }

  // Testing helper to override scheduling state
  void setNextScheduledStream(StreamId id) {
    auto it = writableStreams.find(id);
    CHECK(it != writableStreams.end());
    auto& level = levels[it->second];
    auto streamIt = level.streams.find(id);
    CHECK(streamIt != level.streams.end());
    level.next = streamIt;
  }

  // Only used for testing
  FOLLY_NODISCARD StreamId
  getNextScheduledStream(Priority pri = kDefaultPriority) const {
    auto& level = levels[priority2index(pri, levels.size())];
    if (level.next == level.streams.end()) {
      CHECK(!level.streams.empty());
      return *level.streams.begin();
    }
    return *level.next;
  }

 private:
  folly::F14FastMap<StreamId, size_t> writableStreams;
  using WSIterator = decltype(writableStreams)::iterator;

  WSIterator find(StreamId id) {
    return writableStreams.find(id);
  }

  void eraseFromLevel(size_t levelIndex, StreamId id) {
    auto& level = levels[levelIndex];
    auto streamIt = level.streams.find(id);
    if (streamIt != level.streams.end()) {
      if (streamIt == level.next) {
        level.next = level.streams.erase(streamIt);
      } else {
        level.streams.erase(streamIt);
      }
    } else {
      LOG(DFATAL) << "Stream=" << levelIndex
                  << " not found in PriorityQueue level=" << id;
    }
  }

  // Helper function to erase an iter from writableStream and its corresponding
  // item from levels.
  void erase(WSIterator it) {
    if (it != writableStreams.end()) {
      eraseFromLevel(it->second, it->first);
      writableStreams.erase(it);
    }
  }
};

} // namespace quic
