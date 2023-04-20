/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <initializer_list>

#include <boost/iterator/iterator_facade.hpp>
#include <folly/Portability.h>
#include <folly/memory/Malloc.h>
#include <glog/logging.h>

namespace quic {

/**
 * A container backed by contiguous memory. It can pop and push from both ends
 * like std::deque. Doing such operation with CircularDeque should be faster
 * than std::deque. It also supports APIs to mutate the middle of the container
 * (erase(), emplace() and insert() all support arbitrary positions). But doing
 * so with CircularDeque is much slower than std::deque.
 */
template <typename T>
struct CircularDeque {
  using value_type = T;
  using size_type = std::size_t;
  using reference = T&;
  using const_reference = const T&;
  using difference_type = std::ptrdiff_t;

  CircularDeque() = default;
  CircularDeque(size_type n) {
    resize(n);
  }
  CircularDeque(std::initializer_list<T> init);

  CircularDeque(const CircularDeque& other) {
    *this = other;
  }

  // Move constructor will leave other in a default-initialized state.
  CircularDeque(CircularDeque&& other) noexcept {
    swap(other);
  }

  CircularDeque& operator=(const CircularDeque& other) {
    clear();
    resize(other.size());
    std::uninitialized_copy(other.begin(), other.end(), storage_);
    end_ = other.size();
    return *this;
  }

  // Move assignment will leave other in a default-initialized state.
  CircularDeque& operator=(CircularDeque&& other) noexcept {
    swap(other);
    CircularDeque{}.swap(other);
    return *this;
  }

  CircularDeque& operator=(std::initializer_list<T> ilist);

  ~CircularDeque() {
    if (capacity_ == 0) {
      DCHECK(!storage_);
      return;
    }
    clear();
    folly::sizedFree(storage_, capacity_ * sizeof(T));
    capacity_ = 0;
  }
  // Missing: more constructor overloads, and custom Allocator
  bool operator==(const CircularDeque& other) const {
    return size() == other.size() && std::equal(begin(), end(), other.begin());
  }

  // Iterator
  template <typename U>
  class CircularDequeIterator : public boost::iterator_facade<
                                    CircularDequeIterator<U>,
                                    U,
                                    boost::random_access_traversal_tag> {
   public:
    CircularDequeIterator(const CircularDeque<U>* deque, size_type index)
        : deque_(deque), index_(index) {}

    FOLLY_NODISCARD U& dereference() const {
      return const_cast<U&>(deque_->storage_[index_]);
    }

    FOLLY_NODISCARD bool equal(const CircularDequeIterator<U>& other) const {
      return deque_ == other.deque_ && index_ == other.index_;
    }

    void increment() {
      ++index_;
      auto maxSize = deque_->capacity_;
      if (index_ > maxSize) {
        index_ = 0;
      }
      if (wrapped() && index_ == maxSize) {
        index_ = 0;
      }
    }

    void decrement() {
      auto maxSize = deque_->capacity_;
      if (index_ == 0) {
        index_ = wrapped() ? maxSize - 1 : maxSize;
      } else {
        --index_;
      }
    }

    void advance(difference_type n) {
      if (n == 0) {
        return;
      }
      if (n > 0) {
        auto maxSize = deque_->capacity_;
        index_ = (index_ + n) % (wrapped() ? maxSize : maxSize + 1);
      } else {
        while (n++ != 0) {
          decrement();
        }
      }
    }

    FOLLY_NODISCARD difference_type
    distance_to(const CircularDequeIterator<U>& other) const {
      if (index_ == other.index_) {
        return 0;
      }
      bool backward = false;
      if (wrapped()) {
        if ((index_ >= deque_->begin_ && other.index_ >= deque_->begin_) ||
            (index_ <= deque_->end_ && other.index_ <= deque_->end_)) {
          backward = index_ > other.index_;
        } else {
          backward = index_ < other.index_;
        }
      } else {
        backward = index_ > other.index_;
      }
      difference_type counter = 0;
      auto iter = *this;
      if (backward) {
        while (iter-- != other) {
          --counter;
        }
      } else {
        while (iter++ != other) {
          ++counter;
        }
      }
      return counter;
    }

   private:
    friend class boost::iterator_core_access;
    friend struct CircularDeque<U>;
    friend struct CircularDeque<typename std::remove_const<U>::type>;

    FOLLY_NODISCARD inline bool wrapped() const {
      return deque_->begin_ > deque_->end_;
    }

    const CircularDeque<U>* deque_;
    size_type index_;
  };

  using iterator = CircularDequeIterator<T>;
  using const_iterator = CircularDequeIterator<T>;
  using reverse_iterator = std::reverse_iterator<iterator>;
  using const_reverse_iterator = std::reverse_iterator<const_iterator>;

  FOLLY_NODISCARD bool empty() const noexcept;
  FOLLY_NODISCARD size_type size() const noexcept;

  FOLLY_NODISCARD size_type max_size() const noexcept;
  void resize(size_type count);
  // Missing compared to std::deque:
  // resize(size_t, const T&);
  // shrink_to_fit();

  const_reference operator[](size_type index) const;
  reference operator[](size_type index);
  FOLLY_NODISCARD const_reference at(size_type index) const;
  FOLLY_NODISCARD reference at(size_type index);
  FOLLY_NODISCARD const_reference front() const;
  FOLLY_NODISCARD reference front();
  FOLLY_NODISCARD const_reference back() const;
  FOLLY_NODISCARD reference back();

  FOLLY_NODISCARD iterator begin() noexcept;
  FOLLY_NODISCARD const_iterator begin() const noexcept;
  FOLLY_NODISCARD iterator end() noexcept;
  FOLLY_NODISCARD const_iterator end() const noexcept;
  FOLLY_NODISCARD const_iterator cbegin() const noexcept;
  FOLLY_NODISCARD const_iterator cend() const noexcept;
  FOLLY_NODISCARD reverse_iterator rbegin() noexcept;
  FOLLY_NODISCARD const_reverse_iterator rbegin() const noexcept;
  FOLLY_NODISCARD const_reverse_iterator crbegin() const noexcept;
  FOLLY_NODISCARD reverse_iterator rend() noexcept;
  FOLLY_NODISCARD const_reverse_iterator rend() const noexcept;
  FOLLY_NODISCARD const_reverse_iterator crend() const noexcept;

  template <class... Args>
  reference emplace_front(Args&&... args);
  template <class... Args>
  reference emplace_back(Args&&... args);
  template <class... Args>
  iterator emplace(const_iterator pos, Args&&... args);

  void push_front(const T& val);
  void push_front(T&& val);
  void push_back(const T& val);
  void push_back(T&& val);
  iterator insert(const_iterator pos, const T& val);
  iterator insert(const_iterator pos, T&& val);
  // Missing: a couple insert() overloads

  void pop_front();
  void pop_back();

  // If you are erasing from either end of the container and is only erasing
  // one element, I suggest just use pop_front and pop_back. And if are erasing
  // the whole container, please use clear(). There is nothing wrong with
  // erase() in those cases, but such code are behind an UNLIKELY annotation.
  // The generated code can be slow.
  iterator erase(const_iterator pos);
  iterator erase(const_iterator first, const_iterator last);
  void clear() noexcept;
  void swap(CircularDeque<T>& other) noexcept;

 private:
  FOLLY_NODISCARD bool needSpace() const noexcept;

  template <
      typename U = T,
      typename Iterator,
      std::enable_if_t<std::is_move_assignable<U>::value, int> = 0>
  void moveOrCopy(Iterator first, Iterator last, Iterator destFirst) noexcept(
      std::is_nothrow_move_assignable<T>::value) {
    if (first == last || first == destFirst) {
      return;
    }
    auto iter = first;
    while (iter != last) {
      *destFirst = std::move(*iter++);
      // Different from iter, destFirst cannot reuse increment/advance.
      if (destFirst.index_ == capacity_ - 1) {
        destFirst.index_ = 0;
      } else {
        ++destFirst.index_;
      }
    }
  }

  template <
      typename U = T,
      typename ConstIterator,
      typename Iterator,
      std::enable_if_t<
          !std::is_move_assignable<U>::value &&
              std::is_copy_assignable<U>::value,
          int> = 0>
  void moveOrCopy(
      ConstIterator first,
      ConstIterator last,
      Iterator destFirst) noexcept(std::is_nothrow_copy_assignable<T>::value) {
    static_assert(!std::is_assignable<
                  ConstIterator,
                  decltype(*std::declval<ConstIterator>)>::value);
    if (first == last || first == destFirst) {
      return;
    }
    auto iter = first;
    while (iter != last) {
      *destFirst = *iter++;
      // Different from iter, destFirst cannot reuse increment/advance.
      if (destFirst.index_ == capacity_ - 1) {
        destFirst.index_ = 0;
      } else {
        ++destFirst.index_;
      }
    }
  }

  template <
      typename U = T,
      typename Iterator,
      std::enable_if_t<std::is_move_assignable<U>::value, int> = 0>
  void reverseMoveOrCopy(
      Iterator first,
      Iterator last,
      Iterator destLast) noexcept(std::is_nothrow_move_assignable<T>::value) {
    if (first == last || last == destLast) {
      return;
    }
    auto iter = last;
    while (iter != first) {
      if (destLast.index_ == 0) {
        destLast.index_ = capacity_ - 1;
      } else {
        --destLast.index_;
      }
      *destLast = std::move(*--iter);
    }
  }

  template <
      typename U = T,
      typename ConstIterator,
      typename Iterator,
      std::enable_if_t<
          !std::is_move_assignable<U>::value &&
              std::is_copy_assignable<U>::value,
          int> = 0>
  void reverseMoveOrCopy(
      ConstIterator first,
      ConstIterator last,
      Iterator destLast) noexcept(std::is_nothrow_copy_assignable<T>::value) {
    static_assert(!std::is_assignable<
                  ConstIterator,
                  decltype(*std::declval<ConstIterator>)>::value);
    if (first == last || last == destLast) {
      return;
    }
    auto iter = last;
    while (iter != first) {
      if (destLast.index_ == 0) {
        destLast.index_ = capacity_ - 1;
      } else {
        --destLast.index_;
      }
      *destLast = *--iter;
    }
  }

  template <
      typename U = T,
      std::enable_if_t<std::is_move_constructible<U>::value, int> = 0>
  void allocateWithValueFrom(iterator source, iterator dest) noexcept(
      std::is_nothrow_move_constructible<T>::value) {
    new (&storage_[dest.index_]) T(std::move(*source));
  }

  template <
      typename U = T,
      std::enable_if_t<
          !std::is_move_constructible<U>::value &&
              std::is_copy_constructible<U>::value,
          int> = 0>
  void allocateWithValueFrom(const_iterator source, iterator dest) noexcept(
      std::is_nothrow_copy_constructible<T>::value) {
    new (&storage_[dest.index_]) T(*source);
  }

  size_type wrappedDistance(
      const_iterator first,
      const_iterator last) noexcept {
    if (last.index_ >= first.index_) {
      return last.index_ - first.index_;
    }
    return capacity_ - first.index_ + last.index_;
  }

  void indexSanityCheck(const_iterator iter) noexcept {
    if (begin_ <= end_) {
      DCHECK(begin_ <= iter.index_ && iter.index_ <= end_);
    } else {
      DCHECK(iter.index_ >= begin_ || iter.index_ <= end_);
    }
  }

 private:
  T* storage_ = nullptr;
  size_type capacity_ = 0;
  size_type begin_ = 0;
  size_type end_ = 0;
};
} // namespace quic

#include <quic/common/CircularDeque-inl.h>
