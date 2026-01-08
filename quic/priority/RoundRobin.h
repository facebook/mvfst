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
  bool useIndexMap_{false};
};

} // namespace quic
