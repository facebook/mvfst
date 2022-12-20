/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Optional.h>

namespace quic {

template <typename T, T Unit, template <typename... I> class Container>
IntervalSet<T, Unit, Container>::IntervalSet(
    std::initializer_list<Interval<T, Unit>> intervals) {
  for (auto itr = intervals.begin(); itr != intervals.end(); ++itr) {
    insert(*itr);
  }
}

template <typename T, T Unit, template <typename... I> class Container>
void IntervalSet<T, Unit, Container>::insert(
    const Interval<T, Unit>& interval) {
  auto intersectionRange = intersectingRange(interval);
  auto firstIt = intersectionRange.first;
  auto endIt = intersectionRange.second;
  if (firstIt == endIt) {
    insertVersion_++;
    container_type::insert(firstIt, std::move(interval));
    return;
  }
  // Merge from first to last
  auto originalDifference = firstIt->end - firstIt->start;
  auto last = std::prev(endIt);
  firstIt->start = std::min(interval.start, firstIt->start);
  firstIt->end = std::max(interval.end, last->end);
  auto newDifference = firstIt->end - firstIt->start;
  if (newDifference > originalDifference) {
    insertVersion_++;
  }
  container_type::erase(std::next(firstIt), endIt);
}

template <typename T, T Unit, template <typename... I> class Container>
void IntervalSet<T, Unit, Container>::withdraw(
    const Interval<T, Unit>& interval) {
  auto intersectionRange = intersectingRange(interval);
  auto first = intersectionRange.first;
  auto end = intersectionRange.second;
  if (first == end) {
    // No intersection, doesn't need to do anything
    return;
  }
  auto erasureStart = first;
  auto erasureEnd = end;
  auto last = std::prev(end);
  if (last == first) {
    if (first->start + interval_type::unitValue() <= interval.start &&
        last->end >= interval.end + interval_type::unitValue()) {
      // Special case that the target is a sub-interval of an element
      interval_type toSplit(
          first->start, interval.start - interval_type::unitValue());
      last->start = interval.end + interval_type::unitValue();
      container_type::insert(last, std::move(toSplit));
      return;
    }
  }
  if (first->start + interval_type::unitValue() <= interval.start) {
    // Keep the first element
    ++erasureStart;
    first->end = interval.start - interval_type::unitValue();
  }
  if (last->end >= interval.end + interval_type::unitValue()) {
    // Keep the last element
    erasureEnd = last;
    last->start = interval.end + interval_type::unitValue();
  }
  container_type::erase(erasureStart, erasureEnd);
}

template <typename T, T Unit, template <typename... I> class Container>
bool IntervalSet<T, Unit, Container>::contains(const T& start, const T& end) {
  for (auto itr = container_type::begin(); itr != container_type::end();
       itr++) {
    if (start >= itr->start && end <= itr->end) {
      return true;
    }
    if (start < itr->end) {
      return false;
    }
  }
  return false;
}

template <typename T, T Unit, template <typename... I> class Container>
void IntervalSet<T, Unit, Container>::insert(const T& startIt, const T& endIt) {
  if (startIt > endIt) {
    throw std::invalid_argument("Trying to insert invalid interval");
  }
  insert(Interval<T, Unit>(startIt, endIt));
}

template <typename T, T Unit, template <typename... I> class Container>
void IntervalSet<T, Unit, Container>::insert(const T& point) {
  insert(Interval<T, Unit>(point, point));
}

template <typename T, T Unit, template <typename... I> class Container>
auto IntervalSet<T, Unit, Container>::intersectingRange(
    const Interval<T, Unit>& interval) -> decltype(auto) {
  auto firstIt = std::lower_bound(
      container_type::begin(),
      container_type::end(),
      interval,
      [](const Interval<T, Unit>& a, const Interval<T, Unit>& b) {
        return a.end + interval_type::unitValue() < b.start;
      });
  // Starting with end, everything will be unchanged
  auto endIt = firstIt;
  while (endIt != container_type::end() &&
         endIt->start <= interval.end + interval_type::unitValue()) {
    ++endIt;
  }
  return std::make_pair(firstIt, endIt);
}

template <typename T, T Unit, template <typename... I> class Container>
uint64_t IntervalSet<T, Unit, Container>::insertVersion() const {
  return insertVersion_;
}
} // namespace quic
