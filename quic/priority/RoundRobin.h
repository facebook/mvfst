/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/mvfst-config.h>

#include <quic/common/Optional.h>
#include <quic/priority/PriorityQueue.h>
#include <list>

namespace quic {

class RoundRobin {
 public:
  RoundRobin() = default;
  ~RoundRobin() = default;

  // Moving a std::list invalidates only its past-the-end iterator, so nextIt_
  // has to be re-seated rather than copied whenever it is not on an element -
  // which is always the case for an empty RoundRobin.  Copying would leave
  // nextIt_ pointing into the source list, so it is disallowed.
  RoundRobin(RoundRobin&& other) noexcept;
  RoundRobin& operator=(RoundRobin&& other) noexcept;
  RoundRobin(const RoundRobin&) = delete;
  RoundRobin& operator=(const RoundRobin&) = delete;

  // A turn ends after n calls to consume(), or after that many bytes have been
  // reported to it.  Bytes are the fairer measure when elements differ in how
  // much they write per turn.
  void advanceAfterNext(size_t n);
  void advanceAfterBytes(uint64_t bytes);

  [[nodiscard]] bool empty() const;
  void insert(quic::PriorityQueue::Identifier value);
  bool erase(quic::PriorityQueue::Identifier value);
  quic::PriorityQueue::Identifier getNext(
      const quic::Optional<uint64_t>& bytes);
  [[nodiscard]] quic::PriorityQueue::Identifier peekNext() const;
  void consume(const quic::Optional<uint64_t>& bytes);
  void clear();

 private:
  using ListType = std::list<PriorityQueue::Identifier>;

  void erase(ListType::iterator eraseIt);
  void maybeAdvance();
  void buildIndex();

  ListType list_;
  ListType::iterator nextIt_{list_.end()};
  ValueMap<
      PriorityQueue::Identifier,
      ListType::iterator,
      PriorityQueue::Identifier::hash>
      indexMap_;
  enum class AdvanceType : uint8_t { Nexts, Bytes };
  AdvanceType advanceType_{AdvanceType::Nexts};
  bool useIndexMap_{false};
  uint64_t advanceAfter_{1};
  uint64_t current_{0};
};

} // namespace quic
