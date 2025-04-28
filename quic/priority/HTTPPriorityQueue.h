/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/container/F14Map.h>
#include <quic/priority/PriorityQueue.h>
#include <quic/priority/RoundRobin.h>

#include <utility>

namespace quic {

class HTTPPriorityQueue : public quic::PriorityQueue {
  // Element in the IndexMap.  If incremental is true, index applies to
  // roundRobins_, otherwise it applies to heap_.
  struct IndexMapElem {
    bool incremental : 1;
    uint64_t index : 63;
  };

  using IndexMap =
      folly::F14ValueMap<Identifier, IndexMapElem, Identifier::hash>;

 public:
  class Priority : public quic::PriorityQueue::Priority {
   public:
    using OrderId = uint64_t;

    struct HTTPPriority {
      uint8_t urgency : 3;
      bool paused : 1;
      bool incremental : 1;
      OrderId order : 59;
    };

    // TODO: change default priority to (3, false, false, 0) to match spec
    static constexpr HTTPPriority kDefaultPriority{3, false, true, 0};

    /*implicit*/ Priority(const PriorityQueue::Priority& basePriority);

    Priority(uint8_t u, bool i, OrderId o = 0);

    enum Paused { PAUSED };

    /* implicit */ Priority(Paused) : Priority(0, false, 0) {
      getFields().paused = true;
    }

    Priority(const Priority&) = default;
    Priority& operator=(const Priority&) = default;
    Priority(Priority&&) = default;
    Priority& operator=(Priority&&) = default;
    ~Priority() = default;

    const HTTPPriority* operator->() const {
      return &getFields();
    }

    bool operator==(const Priority& other) const {
      auto asUint64 = toUint64();
      auto otherAsUint64 = other.toUint64();
      if (asUint64 == otherAsUint64) {
        return true;
      }
      // The only other way to be equal is if one is initialized and the other
      // is default
      const static uint64_t kDefaultUint64 = Priority(
                                                 kDefaultPriority.urgency,
                                                 kDefaultPriority.incremental,
                                                 kDefaultPriority.order)
                                                 .toUint64();
      return (kDefaultUint64 == otherAsUint64 && !isInitialized()) ||
          (asUint64 == kDefaultUint64 && !other.isInitialized());
    }

    bool operator<(const Priority& other) const {
      return toUint64() < other.toUint64();
    }

    [[nodiscard]] uint64_t toUint64() const {
      const auto& fields = getFields();
      return (
          (uint64_t(fields.urgency) << 61) | (uint64_t(fields.paused) << 60) |
          (uint64_t(fields.incremental) << 59) | fields.order);
    }

    [[nodiscard]] const HTTPPriority& getFields() const {
      return getPriority<HTTPPriority>();
    }

   private:
    HTTPPriority& getFields() {
      return getPriority<HTTPPriority>();
    }
  };

  void advanceAfterNext(size_t n) {
    for (auto& rr : roundRobins_) {
      rr.advanceAfterNext(n);
    }
  }

  void advanceAfterBytes(uint64_t bytes) {
    for (auto& rr : roundRobins_) {
      rr.advanceAfterBytes(bytes);
    }
  }

  [[nodiscard]] bool empty() const override {
    return heap_.empty() && roundRobinElements_ == 0;
  }

  [[nodiscard]] bool equalPriority(
      const PriorityQueue::Priority& p1,
      const PriorityQueue::Priority& p2) const override {
    return static_cast<const HTTPPriorityQueue::Priority&>(p1) ==
        static_cast<const HTTPPriorityQueue::Priority&>(p2);
  }

  [[nodiscard]] PriorityLogFields toLogFields(
      const PriorityQueue::Priority& pri) const override;

  [[nodiscard]] bool contains(Identifier id) const override {
    return find(id) != quic::none;
  }

  void insertOrUpdate(Identifier id, PriorityQueue::Priority priority) override;

  void updateIfExist(Identifier id, PriorityQueue::Priority priority) override;

  void erase(Identifier id) override;

  void clear() override;

  Identifier getNextScheduledID(
      quic::Optional<uint64_t> previousConsumed) override;

  [[nodiscard]] Identifier peekNextScheduledID() const override;

  void consume(quic::Optional<uint64_t> consumed) override;

  // Note: transactions only reinsert erased transactions at previous priority
  // they don't undo inserts, updates, or consume.
  Transaction beginTransaction() override {
    if (hasOpenTransaction_) {
      rollbackTransaction(makeTransaction());
    }
    hasOpenTransaction_ = true;
    return makeTransaction();
  }

  void commitTransaction(Transaction&&) override {
    if (hasOpenTransaction_) {
      hasOpenTransaction_ = false;
      erased_.clear();
    }
  }

  void rollbackTransaction(Transaction&&) override {
    if (hasOpenTransaction_) {
      for (auto& e : erased_) {
        insert(e.identifier, e.priority);
      }
      erased_.clear();
      hasOpenTransaction_ = false;
    }
  }

  [[nodiscard]] Priority headPriority() const;

 private:
  // Heap Element.  If priority.incremental is true, then Identifier is
  // uninitialized - the element is a placeholder for the RoundRobin at
  // roundRobins_[priority.urgency].
  //
  // In the current design, there are no elements with Incremental priority in
  // the heap.
  struct Element {
    Element(Priority p, Identifier i) : priority(std::move(p)), identifier(i) {}

    Priority priority;
    Identifier identifier;

    bool operator<(const Element& other) const {
      if (priority < other.priority) {
        return true;
      }
      if (other.priority < priority || other.priority->incremental) {
        return false;
      }
      // sequential priorities are equal
      return identifier.asUint64() < other.identifier.asUint64();
    }

    bool operator<=(const Element& other) const {
      return !(other < *this);
    }
  };

  struct FindResult {
    IndexMapElem elem;
    IndexMap::const_iterator indexIt;
  };

  [[nodiscard]] quic::Optional<FindResult> find(Identifier id) const;
  void addIndex(Identifier id, IndexMapElem indexElem);
  void removeIndex(IndexMap::const_iterator it);
  void buildSequentialIndex();
  void destroySequentialIndex();

  void heapifyUp(size_t index);
  void heapifyDown(size_t index);
  void assignIndex(Element& element, size_t index);
  void insert(Identifier id, const Priority& priority);
  bool updateInSequential(IndexMapElem indexElem, Priority priority);
  void eraseImpl(Identifier id, IndexMapElem indexElem);

  [[nodiscard]] const Element* FOLLY_NULLABLE top() const;

  // Holds sequential elements
  std::vector<Element> heap_;
  // Map from id -> RoundRobin or Heap Index
  IndexMap indexMap_;
  // Holds incremental elements
  std::array<RoundRobin, 8> roundRobins_;
  // Holds erased elements from the current transaction
  std::vector<Element> erased_;
  // Count of Round Robin elements in the Queue
  uint32_t roundRobinElements_{0};
  // The index of the first non-empty RoundRobin, or roundRobins_.size()
  uint8_t lowestRoundRobin_{uint8_t(roundRobins_.size())};
  bool hasOpenTransaction_{false};
  bool useIndexMapForSequential_{false};
};

} // namespace quic
