/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <algorithm>
#include <iterator>

#include <folly/Likely.h>
#include <folly/ScopeGuard.h>

namespace quic {

constexpr size_t kInitCapacity = 500;
constexpr size_t kResizeFactor = 2;

template <typename T>
CircularDeque<T>::CircularDeque(std::initializer_list<T> init) {
  *this = std::move(init);
}

template <typename T>
CircularDeque<T>& CircularDeque<T>::operator=(std::initializer_list<T> ilist) {
  clear();
  if (ilist.size() > max_size()) {
    resize(ilist.size());
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
  DCHECK_LE(size(), max_size());
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
      reinterpret_cast<T*>(folly::checkedMalloc(newCapacity * sizeof(T)));
  SCOPE_FAIL {
    folly::sizedFree(newStorage, newCapacity * sizeof(T));
  };
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
  return *(begin() + index);
}

template <typename T>
typename CircularDeque<T>::reference CircularDeque<T>::operator[](
    size_type index) {
  return *(begin() + index);
}

template <typename T>
typename CircularDeque<T>::const_reference CircularDeque<T>::at(
    size_type index) const {
  if (index >= size()) {
    throw std::out_of_range("Out of bound access");
  }
  return operator[](index);
}

template <typename T>
typename CircularDeque<T>::reference CircularDeque<T>::at(size_type index) {
  if (index >= size()) {
    throw std::out_of_range("Out of bound access");
  }
  return operator[](index);
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
    resize(capacity_ == 0 ? kInitCapacity : capacity_ * kResizeFactor);
  }
  if (begin_ == 0) {
    DCHECK_NE(end_, capacity_ - 1);
    begin_ = capacity_ - 1;
  } else {
    DCHECK_NE(end_, begin_ - 1);
    --begin_;
  }
  new (&storage_[begin_]) T(std::forward<Args>(args)...);
  DCHECK_NE(begin_, end_);
  return front();
}

template <typename T>
template <class... Args>
typename CircularDeque<T>::reference CircularDeque<T>::emplace_back(
    Args&&... args) {
  if (needSpace()) {
    resize(capacity_ == 0 ? kInitCapacity : capacity_ * kResizeFactor);
  }
  DCHECK_GT(capacity_, 0);
  if (end_ == capacity_) {
    end_ = 0;
    DCHECK_NE(0, begin_);
  }
  new (&storage_[end_++]) T(std::forward<Args>(args)...);
  DCHECK_NE(begin_, end_);
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
    DCHECK_NE(begin_, end_);
    return CircularDequeIterator<T>(this, end_ == 0 ? capacity_ - 1 : end_ - 1);
  }
  if (index == begin_) {
    emplace_front(std::forward<Args>(args)...);
    DCHECK_NE(begin_, end_);
    return begin();
  }

  // Similar to erase(), emplace() in the middle is expensive
  auto dist = std::distance(begin(), pos);
  if (needSpace()) {
    resize(capacity_ * kResizeFactor);
    // After resize, pos is invalid. We need to find the new pos.
    pos = begin() + dist;
    index = pos.index_;
  }
  auto distIfMoveFront = wrappedDistance(begin(), pos);
  auto distIfMoveBack = wrappedDistance(pos, end());
  auto lastGoodIndex = capacity_ - 1;
  if (distIfMoveBack <= distIfMoveFront) {
    auto prev =
        CircularDequeIterator<T>(this, end_ == 0 ? lastGoodIndex : end_ - 1);
    allocateWithValueFrom(prev, end());
    reverseMoveOrCopy(pos, end() - 1, end());
    storage_[index] = T(std::forward<Args>(args)...);
    end_ = (end() + 1).index_;
  } else {
    auto destIndex = begin_ == 0 ? lastGoodIndex : begin_ - 1;
    auto destIter = CircularDequeIterator<T>(this, destIndex);
    allocateWithValueFrom(begin(), destIter);
    moveOrCopy(begin() + 1, pos, begin());
    index = index == 0 ? index = lastGoodIndex : index - 1;
    storage_[index] = T(std::forward<Args>(args)...);
    begin_ = destIndex;
  }
  // We resized before. They can't be at the same place even if we had to move
  // end_ forward above.
  DCHECK_NE(begin_, end_);
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
  storage_[begin_].~T();
  // This if branch is actually faster than operator% on the machine I tested.
  if (++begin_ == capacity_) {
    begin_ = 0;
  }
}

template <typename T>
void CircularDeque<T>::pop_back() {
  if (end_ == 0) {
    end_ = capacity_;
  }
  --end_;
  storage_[end_].~T();
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
  DCHECK_NE(first.index_, capacity_);
  if (first == last) {
    return CircularDequeIterator<T>(this, last.index_);
  }
  if (begin_ < end_) {
    DCHECK(
        begin_ <= first.index_ && first.index_ <= last.index_ &&
        last.index_ <= end_);
  } else {
    DCHECK(first.index_ <= end_ || first.index_ >= begin_);
    DCHECK(last.index_ <= end_ || last.index_ >= begin_);
  }
  if (UNLIKELY(wrappedDistance(first, last) == size())) {
    // if we are erasing everything, just clear()
    clear();
    // The return iterator in this case isn't legit.
    return end();
  }
  if (first == begin() || last == end()) {
    // If we are erasing from either end, destructing the member and adjust the
    // index then we are done.
    auto iter = first;
    while (iter != last) {
      indexSanityCheck(iter);
      iter++->~T();
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
  auto currentSize = size();
  auto elemsRemoved = std::distance(first, last);
  DCHECK_GE(elemsRemoved, 0)
      << "first=" << first.index_ << ", last=" << last.index_
      << ", distance=" << elemsRemoved << ", maxSize=" << max_size()
      << ", begin=" << begin_ << ", end=" << end_;
  auto distIfMoveFront = wrappedDistance(cbegin(), first);
  auto distIfMoveBack = wrappedDistance(last, cend());
  if (distIfMoveFront < distIfMoveBack) {
    auto newBegin = last - (first - begin());
    // This needs to go reverse direction in case the source and destination
    // ranges overlap.
    reverseMoveOrCopy(begin(), first, last);
    auto iter = begin();
    while (iter != newBegin) {
      iter++->~T();
    }
    begin_ = newBegin.index_;
    DCHECK_EQ(size(), currentSize - elemsRemoved)
        << "size=" << size() << ", currentSize=" << currentSize
        << ", elemsRemoved=" << elemsRemoved;
    return CircularDequeIterator<T>(this, last.index_);
  }
  moveOrCopy(last, end(), first);
  auto newEnd = end() - elemsRemoved;
  auto iter = newEnd;
  while (iter != end()) {
    iter++->~T();
  }
  end_ = newEnd.index_;
  DCHECK(size() == currentSize - elemsRemoved);
  return CircularDequeIterator<T>(this, first.index_);
}

template <typename T>
void CircularDeque<T>::clear() noexcept {
  if (empty() || capacity_ == 0) {
    return;
  }
  auto iter = begin();
  while (iter != end()) {
    iter++->~T();
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
