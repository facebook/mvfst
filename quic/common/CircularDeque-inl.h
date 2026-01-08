/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>
#include <algorithm>
#include <cstdlib>
#include <iterator>
#include <memory>

namespace quic {

// Allocates memory and aborts on failure instead of throwing exceptions
inline void* checkedMalloc(size_t size) {
  void* ptr = ::operator new(size, std::nothrow);
  if (!ptr && size > 0) {
    std::abort();
  }
  return ptr;
}

constexpr size_t kInitCapacity = 10;
constexpr size_t kGrowthNumerator = 3;
constexpr size_t kGrowthDenominator = 2;

inline size_t growCapacity(size_t currentCapacity) {
  return (currentCapacity * kGrowthNumerator) / kGrowthDenominator;
}

template <typename T>
CircularDeque<T>::CircularDeque(std::initializer_list<T> init) {
  *this = std::move(init);
}

template <typename T>
CircularDeque<T>& CircularDeque<T>::operator=(std::initializer_list<T> ilist) {
  clear();
  if (ilist.size() > max_size()) {
    resize(std::max(ilist.size(), kInitCapacity));
  }
  std::uninitialized_copy(ilist.begin(), ilist.end(), storage_);
  end_ = ilist.size();
  return *this;
}

template <typename T>
bool CircularDeque<T>::needSpace() const noexcept {
  /**
   * size() and capacity can't be eq. Otherwise begin_ and end_ may point to the
   * same position, in which case I don't know if my container is full or empty.
   */
  MVDCHECK_LE(size(), max_size());
  return size() == max_size();
}

template <typename T>
bool CircularDeque<T>::empty() const noexcept {
  return begin_ == end_;
}

template <typename T>
typename CircularDeque<T>::size_type CircularDeque<T>::size() const noexcept {
  return end_ - begin_ + (end_ < begin_ ? capacity_ : 0);
}

template <typename T>
typename CircularDeque<T>::size_type CircularDeque<T>::max_size()
    const noexcept {
  // See the comments in resize() to see why this needs to minus 1.
  return capacity_ == 0 ? 0 : capacity_ - 1;
}

template <typename T>
void CircularDeque<T>::resize(size_type count) {
  if (max_size() == count) {
    return;
  }
  // The way we wrap around begin_ and end_ means for a vector of size S, we can
  // only store (S - 1) elements in them.
  auto newCapacity = count + 1;
  auto newSize = std::min(count, size());
  auto newStorage =
      reinterpret_cast<T*>(checkedMalloc(newCapacity * sizeof(T)));
  if constexpr (std::is_move_constructible_v<T>) {
    std::uninitialized_move(begin(), end(), newStorage);
  } else {
    std::uninitialized_copy(begin(), end(), newStorage);
  }
  CircularDeque{}.swap(*this);
  storage_ = newStorage;
  capacity_ = newCapacity;
  end_ = newSize;
}

template <typename T>
typename CircularDeque<T>::const_reference CircularDeque<T>::operator[](
    size_type index) const {
  MVCHECK_LT(index, size(), "CircularDeque index out of bounds");
  return *(begin() + index);
}

template <typename T>
typename CircularDeque<T>::reference CircularDeque<T>::operator[](
    size_type index) {
  MVCHECK_LT(index, size(), "CircularDeque index out of bounds");
  return *(begin() + index);
}

template <typename T>
typename CircularDeque<T>::const_reference CircularDeque<T>::front() const {
  return storage_[begin_];
}

template <typename T>
typename CircularDeque<T>::reference CircularDeque<T>::front() {
  return storage_[begin_];
}

template <typename T>
typename CircularDeque<T>::const_reference CircularDeque<T>::back() const {
  return storage_[(end_ == 0 ? capacity_ : end_) - 1];
}

template <typename T>
typename CircularDeque<T>::reference CircularDeque<T>::back() {
  return storage_[(end_ == 0 ? capacity_ : end_) - 1];
}

template <typename T>
typename CircularDeque<T>::iterator CircularDeque<T>::begin() noexcept {
  return CircularDequeIterator<T>(this, begin_);
}

template <typename T>
typename CircularDeque<T>::const_iterator CircularDeque<T>::begin()
    const noexcept {
  return CircularDeque<T>::const_iterator(this, begin_);
}

template <typename T>
typename CircularDeque<T>::iterator CircularDeque<T>::end() noexcept {
  return CircularDequeIterator<T>(this, end_);
}

template <typename T>
typename CircularDeque<T>::const_iterator CircularDeque<T>::end()
    const noexcept {
  return CircularDeque<T>::const_iterator(this, end_);
}

template <typename T>
typename CircularDeque<T>::const_iterator CircularDeque<T>::cbegin()
    const noexcept {
  return CircularDeque<T>::const_iterator(this, begin_);
}

template <typename T>
typename CircularDeque<T>::const_iterator CircularDeque<T>::cend()
    const noexcept {
  return CircularDeque<T>::const_iterator(this, end_);
}

template <typename T>
typename CircularDeque<T>::reverse_iterator
CircularDeque<T>::rbegin() noexcept {
  return CircularDeque<T>::reverse_iterator(end());
}

template <typename T>
typename CircularDeque<T>::const_reverse_iterator CircularDeque<T>::rbegin()
    const noexcept {
  return CircularDeque<T>::const_reverse_iterator(end());
}

template <typename T>
typename CircularDeque<T>::reverse_iterator CircularDeque<T>::rend() noexcept {
  return CircularDeque<T>::reverse_iterator(begin());
}

template <typename T>
typename CircularDeque<T>::const_reverse_iterator CircularDeque<T>::rend()
    const noexcept {
  return CircularDeque<T>::const_reverse_iterator(begin());
}

template <typename T>
typename CircularDeque<T>::const_reverse_iterator CircularDeque<T>::crbegin()
    const noexcept {
  return CircularDeque<T>::const_reverse_iterator(end());
}

template <typename T>
typename CircularDeque<T>::const_reverse_iterator CircularDeque<T>::crend()
    const noexcept {
  return CircularDeque<T>::const_reverse_iterator(begin());
}

template <typename T>
template <class... Args>
typename CircularDeque<T>::reference CircularDeque<T>::emplace_front(
    Args&&... args) {
  if (needSpace()) {
    resize(capacity_ == 0 ? kInitCapacity : growCapacity(capacity_));
  }
  if (begin_ == 0) {
    MVDCHECK_NE(end_, capacity_ - 1);
    begin_ = capacity_ - 1;
  } else {
    MVDCHECK_NE(end_, begin_ - 1);
    --begin_;
  }
  new (&storage_[begin_]) T(std::forward<Args>(args)...);
  MVDCHECK_NE(begin_, end_);
  return front();
}

template <typename T>
template <class... Args>
typename CircularDeque<T>::reference CircularDeque<T>::emplace_back(
    Args&&... args) {
  if (needSpace()) {
    resize(capacity_ == 0 ? kInitCapacity : growCapacity(capacity_));
  }
  MVDCHECK_GT(capacity_, 0);
  if (end_ == capacity_) {
    end_ = 0;
    MVDCHECK_NE(0, begin_);
  }
  new (&storage_[end_++]) T(std::forward<Args>(args)...);
  MVDCHECK_NE(begin_, end_);
  return back();
}

template <typename T>
template <class... Args>
typename CircularDeque<T>::iterator CircularDeque<T>::emplace(
    typename CircularDeque<T>::const_iterator pos,
    Args&&... args) {
  // Front and back can take shortcuts. Also the resize() will be taken care of
  // by the emplace_front() and emplace_back().
  auto index = pos.index_;
  if (index == end_) {
    emplace_back(std::forward<Args>(args)...);
    MVDCHECK_NE(begin_, end_);
    return CircularDequeIterator<T>(this, end_ == 0 ? capacity_ - 1 : end_ - 1);
  }
  if (index == begin_) {
    emplace_front(std::forward<Args>(args)...);
    MVDCHECK_NE(begin_, end_);
    return begin();
  }

  // Similar to erase(), emplace() in the middle is expensive
  auto dist = std::distance(cbegin(), pos);
  if (needSpace()) {
    resize(growCapacity(capacity_));
    // After resize, pos is invalid. We need to find the new pos.
    pos = cbegin() + dist;
    index = pos.index_;
  }
  auto distIfMoveFront = wrappedDistance(cbegin(), pos);
  auto distIfMoveBack = wrappedDistance(pos, cend());
  auto lastGoodIndex = capacity_ - 1;
  if (distIfMoveBack <= distIfMoveFront) {
    auto prev =
        CircularDequeIterator<T>(this, end_ == 0 ? lastGoodIndex : end_ - 1);
    auto wrappedEnd = end_ == capacity_ ? end() + 1 : end();
    allocateWithValueFrom(prev, wrappedEnd);
    // Convert const_iterator to iterator for template matching
    auto posMutable = begin() + (pos - cbegin());
    reverseMoveOrCopy(posMutable, end() - 1, end());
    storage_[index] = T(std::forward<Args>(args)...);
    end_ = (wrappedEnd + 1).index_;
  } else {
    auto destIndex = begin_ == 0 ? lastGoodIndex : begin_ - 1;
    auto destIter = CircularDequeIterator<T>(this, destIndex);
    allocateWithValueFrom(begin(), destIter);
    // Convert const_iterator to iterator for template matching
    auto posMutable = begin() + (pos - cbegin());
    moveOrCopy(begin() + 1, posMutable, begin());
    index = index == 0 ? lastGoodIndex : index - 1;
    storage_[index] = T(std::forward<Args>(args)...);
    begin_ = destIndex;
  }
  // We resized before. They can't be at the same place even if we had to move
  // end_ forward above.
  MVDCHECK_NE(begin_, end_);
  return CircularDequeIterator<T>(this, index);
}

template <typename T>
void CircularDeque<T>::push_front(const T& val) {
  emplace_front(val);
}

template <typename T>
void CircularDeque<T>::push_front(T&& val) {
  emplace_front(std::move(val));
}

template <typename T>
void CircularDeque<T>::push_back(const T& val) {
  emplace_back(val);
}

template <typename T>
void CircularDeque<T>::push_back(T&& val) {
  emplace_back(std::move(val));
}

template <typename T>
typename CircularDeque<T>::iterator CircularDeque<T>::insert(
    typename CircularDeque<T>::const_iterator pos,
    const T& val) {
  return emplace(pos, val);
}

template <typename T>
typename CircularDeque<T>::iterator CircularDeque<T>::insert(
    typename CircularDeque<T>::const_iterator pos,
    T&& val) {
  return emplace(pos, std::move(val));
}

template <typename T>
void CircularDeque<T>::pop_front() {
  if constexpr (!std::is_trivially_destructible_v<T>) {
    std::destroy_at(&storage_[begin_]);
  }
  // This if branch is actually faster than operator% on the machine I tested.
  if (++begin_ == capacity_) {
    begin_ = 0;
    if (end_ == capacity_) {
      end_ = begin_;
    }
  }
}

template <typename T>
void CircularDeque<T>::pop_back() {
  if (end_ == 0) {
    end_ = capacity_;
  }
  --end_;
  if constexpr (!std::is_trivially_destructible_v<T>) {
    std::destroy_at(&storage_[end_]);
  }
}

template <typename T>
typename CircularDeque<T>::iterator CircularDeque<T>::erase(
    typename CircularDeque<T>::const_iterator pos) {
  return erase(pos, pos + 1);
}

template <typename T>
typename CircularDeque<T>::iterator CircularDeque<T>::erase(
    typename CircularDeque<T>::const_iterator first,
    typename CircularDeque<T>::const_iterator last) {
  if (first == last) {
    return CircularDequeIterator<T>(this, last.index_);
  }
  if (begin_ < end_) {
    MVDCHECK(
        begin_ <= first.index_ && first.index_ <= last.index_ &&
        last.index_ <= end_);
  } else {
    MVDCHECK(first.index_ <= end_ || first.index_ >= begin_);
    MVDCHECK(last.index_ <= end_ || last.index_ >= begin_);
  }
  if (wrappedDistance(first, last) == size()) {
    // if we are erasing everything, just clear()
    clear();
    // The return iterator in this case isn't legit.
    return end();
  }
  if (first == begin() || last == end()) {
    // If we are erasing from either end, destructing the member and adjust the
    // index then we are done.
    if constexpr (!std::is_trivially_destructible_v<T>) {
      for (auto iter = first; iter != last; ++iter) {
        indexSanityCheck(iter);
        std::destroy_at(&*iter);
      }
    }
    if (first == begin()) {
      begin_ = last.index_;
      return CircularDequeIterator<T>(this, last.index_);
    } else {
      end_ = first.index_;
      return CircularDequeIterator<T>(this, first.index_);
    }
  }

  // Erasing from middle is hard. We will need to move some of the remaining
  // elements to fill up the hole it creates.
  [[maybe_unused]] auto currentSize = size();
  auto elemsRemoved = std::distance(first, last);
  MVDCHECK_GE(
      elemsRemoved,
      0,
      "first=" << first.index_ << ", last=" << last.index_
               << ", distance=" << elemsRemoved << ", maxSize=" << max_size()
               << ", begin=" << begin_ << ", end=" << end_);
  auto distIfMoveFront = wrappedDistance(cbegin(), first);
  auto distIfMoveBack = wrappedDistance(last, cend());
  if (distIfMoveFront < distIfMoveBack) {
    auto newBegin = last - (first - cbegin());
    // This needs to go reverse direction in case the source and destination
    // ranges overlap.
    // Convert const_iterator to iterator for template matching
    auto firstMutable = begin() + (first - cbegin());
    auto lastMutable = begin() + (last - cbegin());
    reverseMoveOrCopy(begin(), firstMutable, lastMutable);
    auto newBeginMutable = begin() + (newBegin - cbegin());
    if constexpr (!std::is_trivially_destructible_v<T>) {
      for (auto iter = begin(); iter != newBeginMutable; ++iter) {
        std::destroy_at(&*iter);
      }
    }
    begin_ = newBegin.index_;
    MVDCHECK_EQ(
        size(),
        currentSize - elemsRemoved,
        "size=" << size() << ", currentSize=" << currentSize
                << ", elemsRemoved=" << elemsRemoved);
    return CircularDequeIterator<T>(this, last.index_);
  }
  // Convert const_iterator to iterator for template matching
  auto lastMutable = begin() + (last - cbegin());
  auto firstMutable = begin() + (first - cbegin());
  moveOrCopy(lastMutable, end(), firstMutable);
  auto newEnd = end() - elemsRemoved;
  if constexpr (!std::is_trivially_destructible_v<T>) {
    for (auto iter = newEnd; iter != end(); ++iter) {
      std::destroy_at(&*iter);
    }
  }
  end_ = newEnd.index_;
  MVDCHECK(size() == currentSize - elemsRemoved);
  return CircularDequeIterator<T>(this, first.index_);
}

template <typename T>
void CircularDeque<T>::clear() noexcept {
  if (empty() || capacity_ == 0) {
    return;
  }
  if constexpr (!std::is_trivially_destructible_v<T>) {
    for (auto iter = begin(); iter != end(); ++iter) {
      std::destroy_at(&*iter);
    }
  }
  begin_ = 0;
  end_ = 0;
}

template <typename T>
void CircularDeque<T>::swap(CircularDeque<T>& other) noexcept {
  using std::swap;
  swap(storage_, other.storage_);
  swap(capacity_, other.capacity_);
  swap(begin_, other.begin_);
  swap(end_, other.end_);
}

} // namespace quic
