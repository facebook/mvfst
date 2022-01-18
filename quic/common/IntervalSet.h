/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <algorithm>
#include <cstdint>
#include <exception>
#include <queue>
#include <stdexcept>

#include <folly/Likely.h>

namespace quic {

constexpr uint64_t kDefaultIntervalSetVersion = 0;

template <typename T, T Unit = (T)1>
struct Interval {
  T start;
  T end;
  static constexpr T unitValue() {
    return Unit;
  }
  Interval(const T& s, const T& e) : start(s), end(e) {
    if (start > end) {
      throw std::invalid_argument("Trying to construct invalid interval");
    }
    if (end > std::numeric_limits<T>::max() - unitValue()) {
      throw std::invalid_argument("Interval bound too large");
    }
  }

  bool operator==(Interval& rhs) const {
    return start == rhs.start && end == rhs.end;
  }

  friend bool operator==(const Interval& a, const Interval& b) {
    return a.start == b.start && a.end == b.end;
  }
};

/*
 * IntervalSet conceptually represents a set of sorted disjoint intervals.
 * Any operations on top of an interval set should keep the intervals it holds
 * sorted and disjoint. For example, insertion might trigger a merge of multiple
 * intervals. This implementation exposes API for insertion at  arbitrary place
 * but consumption only takes place at the beginning or the end. This
 * simplyfies the internal implementation. Also, still for the sake of
 * simplicity, it only exposes const iterator to users.
 */
template <
    typename T,
    T Unit = (T)1,
    template <typename... I> class Container = std::deque>
class IntervalSet : private Container<Interval<T, Unit>> {
 public:
  using interval_type = Interval<T, Unit>;
  using container_type = Container<Interval<T, Unit>>;
  using value_type = typename container_type::value_type;

  // Only allow const access to simplify implementation
  using const_iterator = typename container_type::const_iterator;
  using const_reverse_iterator =
      typename container_type::const_reverse_iterator;

  IntervalSet() {}

  IntervalSet(std::initializer_list<interval_type> intervals);

  // Range-based for loops expect begin and end to be available, and there's no
  // way to force them to instead use cbegin and cend. To provide support for
  // range-based for loops while still meeting our requirement that changes to
  // the set's contents should only be made through the exposed accessors,
  // expose begin and end as const iterators.

  auto begin() const {
    return container_type::cbegin();
  }

  auto end() const {
    return container_type::cend();
  }

  void insert(const Interval<T, Unit>& interval);

  void insert(const T& start, const T& end);

  void insert(const T& point);

  void withdraw(const Interval<T, Unit>& interval);

  /**
   * The version changes whenever we insert into the ack list.
   */
  uint64_t insertVersion() const;

  bool operator==(const IntervalSet& rhs) const {
    return static_cast<container_type>(*this) ==
        static_cast<container_type>(rhs);
  }

  bool operator!=(const IntervalSet& rhs) const {
    return static_cast<container_type>(*this) !=
        static_cast<container_type>(rhs);
  }

  using container_type::back;
  using container_type::cbegin;
  using container_type::cend;
  using container_type::clear;
  using container_type::crbegin;
  using container_type::crend;
  using container_type::empty;
  using container_type::front;
  using container_type::pop_back;
  using container_type::size;

 private:
  /**
   * Helper function to find the intersecting range in this interval set
   * for the interval passed in. It returns a pair of iterator denoting
   * [first, end) in the traditional stl iterator sense where first is the first
   * block that overlaps the interval and end is the last block that is > the
   * interval.
   */
  auto intersectingRange(const interval_type& interval) -> decltype(auto);

  uint64_t insertVersion_{kDefaultIntervalSetVersion};
};
} // namespace quic
#include <quic/common/IntervalSet-inl.h>
