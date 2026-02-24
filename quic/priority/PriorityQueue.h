/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/MvfstLogging.h>
#include <quic/common/Optional.h>
#include <array>
#include <vector>

namespace quic {
/*
 * Generic Priority Queue interface for QUIC and HTTP stream egress
 *
 * Example usage:
 *
 * buildPacket(queue) {
 *  auto txn = queue.beginTransaction();
 *  while (!queue.empty() && spaceLeftInPacket) {
 *    auto nextID = queue.peekNextScheduledID();
 *    previousWritten = addBytesToPacket(packet, nextID, &spaceLeftInPacket);
 *    if (!streamWritable(nextID)) {
 *      queue.erase(nextID);
 *    } else {
 *      queue.consume(previousWritten);
 *    }
 *  }
 * }
 *
 * sendBuiltPackets(queue, Transaction txn, ...) {
 *   sent = send(...);
 *   if (sent) {
 *     queue.commit(std::move(txn));
 *   } else {
 *     queue.rollback(std::move(txn));
 *   }
 */

class PriorityQueue {
 public:
  // Generic Identifier for either a QUIC stream or arbitrary datagram flow ID
  // Since QUIC streams are limited to 2^62-1, we can use the high order bits
  // of value to indicate the type.
  struct Identifier {
    // For now, this is restricted to 2 bits.  However, there's plenty of
    // type space under 0x40 because datagram flow IDs are 32 bits.
    // clang-format off
    enum class Type : uint8_t {
      STREAM = 0x00,         // 0000 0000
      DATAGRAM = 0x40,       // 0100 0000
      // Unused = 0x80,      // 1000 0000
      UNINITIALIZED = 0xC0,  // 1100 0000
    };
    // clang-format on
    static constexpr uint8_t kTypeShift = 56;
    static constexpr uint64_t kTypeMask =
        static_cast<uint64_t>(Type::UNINITIALIZED) << kTypeShift;
    Identifier() = default;

    static Identifier fromStreamID(uint64_t streamID) {
      MVCHECK_LT(streamID, 1LLU << 62);
      return Identifier(streamID);
    }

    static Identifier fromDatagramFlowID(uint32_t flowID) {
      return Identifier((uint64_t(Type::DATAGRAM) << kTypeShift) | flowID);
    }

    [[nodiscard]] Type getType() const noexcept {
      return Type((value & kTypeMask) >> kTypeShift);
    }

    [[nodiscard]] bool isStreamID() const noexcept {
      return getType() == Type::STREAM;
    }

    [[nodiscard]] bool isDatagramFlowID() const noexcept {
      return getType() == Type::DATAGRAM;
    }

    [[nodiscard]] bool isInitialized() const noexcept {
      return getType() != Type::UNINITIALIZED;
    }

    [[nodiscard]] uint64_t asStreamID() const noexcept {
      MVCHECK(isStreamID());
      return value & ~kTypeMask;
    }

    [[nodiscard]] uint32_t asDatagramFlowID() const noexcept {
      MVCHECK(isDatagramFlowID());
      return uint32_t(value); // truncating the top works
    }

    [[nodiscard]] uint64_t asUint64() const noexcept {
      return value & ~kTypeMask;
    }

    bool operator==(const Identifier& other) const noexcept {
      return value == other.value;
    }

    struct hash {
      size_t operator()(const Identifier& id) const {
        return std::hash<uint64_t>()(id.value);
      }
    };

   private:
    explicit Identifier(uint64_t v) : value(v) {}

    uint64_t value{uint64_t(Type::UNINITIALIZED) << kTypeShift};
  };

  // Abstract class representing priority. Concrete implementations of the queue
  // will define their own priority structure.
  class Priority {
   public:
    Priority() : storage_{kUninitialized} {}

    Priority(const Priority&) = default;
    Priority& operator=(const Priority&) = default;

    ~Priority() = default;

    [[nodiscard]] bool isInitialized() const noexcept {
      return storage_ != kUninitialized;
    }

   protected:
    using StorageType = std::array<uint8_t, 16>;

    template <typename T>
    T& getPriority() {
      static_assert(
          std::is_trivially_copyable_v<T> && std::is_standard_layout_v<T>,
          "T must be trivially copyable and standard layout");
      static_assert(sizeof(T) <= sizeof(StorageType), "T must fit in storage_");
      return *reinterpret_cast<T*>(storage_.data());
    }

    template <typename T>
    const T& getPriority() const {
      static_assert(
          std::is_trivially_copyable_v<T> && std::is_standard_layout_v<T>,
          "T must be trivially copyable and standard layout");
      static_assert(sizeof(T) <= sizeof(StorageType), "T must fit in storage_");
      return *reinterpret_cast<const T*>(storage_.data());
    }

   private:
    // clang-format off
    static constexpr StorageType kUninitialized = {
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    // clang-format on
    alignas(sizeof(StorageType)) StorageType storage_;
  };

  virtual ~PriorityQueue() = default;

  // Returns true if the queue contains ID, false otherwise
  [[nodiscard]] virtual bool contains(Identifier id) const noexcept = 0;

  // Returns true if the queue contains no elements, false otherwise
  [[nodiscard]] virtual bool empty() const noexcept = 0;

  // Convert the Priority to JSON string.
  using PriorityLogFields = std::vector<std::pair<std::string, std::string>>;
  [[nodiscard]] virtual PriorityLogFields toLogFields(
      const Priority& pri) const = 0;

  // Compare two Priority's for equality
  [[nodiscard]] virtual bool equalPriority(
      const Priority& p1,
      const Priority& p2) const = 0;

  // Add the given id to the priority queue with the given priority.  If it
  // already exists in the queue, update it to the specified priority.
  virtual void insertOrUpdate(Identifier id, Priority priority) = 0;

  // Update the priority of id if it exists in the queue, otherwise no-op
  virtual void updateIfExist(Identifier id, Priority priority) = 0;

  // Remove the ID from the queue
  virtual void erase(Identifier id) = 0;

  // Remove all entries from the queue
  virtual void clear() = 0;

  // Return the highest priority identifier in the queue.  It is an error to
  // call this if the queue is empty, returns an uninitialized Identifier.
  // For stateful queues (eg: a round-robin queue), this method can mutate the
  // state, such that the next call to getNextScheduledID returns some other
  // value.
  //
  // previousConsumed indicates how many resources the previously returned ID
  // consumed.  This can be used by a stateful queue that wants to ensure
  // fairness of resource usage before advancing.
  virtual Identifier getNextScheduledID(
      quic::Optional<uint64_t> previousConsumed) = 0;

  [[nodiscard]] virtual Priority headPriority() const = 0;

  // Return the highest priority identifier in the queue, but does not
  // mutate any state.  Calling this repeatedly will return the same value.
  // It is an error to call this on an empty queue.
  [[nodiscard]] virtual Identifier peekNextScheduledID() const = 0;

  virtual void consume(quic::Optional<uint64_t> consumed) = 0;

  class Transaction;

  // Begin a transaction with the queue.  Transactions are optional, but are
  // useful for conditionally erasing/dequeuing elements with the ability to
  // rollback (reinsert them).
  virtual Transaction beginTransaction() = 0;

  // Commit the current transaction.  All ID erasures since beginTransaction
  // become permanent.
  virtual void commitTransaction(Transaction&&) = 0;

  // Rollback the current transaction  All IDs erased since beginTransaction
  // are re-inserted at their previous priority level.
  virtual void rollbackTransaction(Transaction&&) = 0;

 protected:
  Transaction makeTransaction();
};

class PriorityQueue::Transaction {
 public:
  ~Transaction() = default;
  Transaction(Transaction&&) noexcept = default;
  Transaction& operator=(Transaction&&) noexcept = default;
  Transaction(const Transaction&) = delete;
  Transaction& operator=(const Transaction&) = delete;

 private:
  friend class PriorityQueue;
  Transaction() = default;
};

inline PriorityQueue::Transaction PriorityQueue::makeTransaction() {
  return {};
}
} // namespace quic
