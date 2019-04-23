/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook.  All rights reserved.
#pragma once

#include <boost/iterator/iterator_facade.hpp>
#include <boost/variant/static_visitor.hpp>
#include <folly/Overload.h>
#include <quic/codec/Types.h>
#include <algorithm>
#include <vector>

namespace quic {

template <class Frame>
struct frame_visitor : public boost::static_visitor<bool> {
  template <class T>
  bool operator()(const T& /*f*/) const {
    return std::is_same<T, Frame>::value;
  }
};

template <class Frame, class FrameType>
bool matchesPredicate(const FrameType& quicFrame) {
  return boost::apply_visitor(frame_visitor<Frame>(), quicFrame);
}

template <class Frame, class FrameType>
class frame_iterator : public boost::iterator_facade<
                           frame_iterator<Frame, FrameType>,
                           Frame const,
                           boost::forward_traversal_tag> {
 public:
  explicit frame_iterator(const std::vector<FrameType>& data) : data_(data) {
    // Maintain the invariant that we're always pointing to the
    // first frame that matches.
    current_ = std::find_if(
        data_.begin(), data_.end(), matchesPredicate<Frame, FrameType>);
  }
  frame_iterator(
      const std::vector<FrameType>& data,
      typename std::vector<FrameType>::const_iterator pos)
      : data_(data), current_(pos) {}

 private:
  friend class boost::iterator_core_access;
  void increment() {
    current_ = std::find_if(
        current_ + 1, data_.end(), matchesPredicate<Frame, FrameType>);
  }

  bool equal(frame_iterator const& other) const {
    return current_ == other.current_;
  }

  const Frame& dereference() const {
    return boost::get<Frame>(*current_);
  }

 private:
  const std::vector<FrameType>& data_;
  typename std::vector<FrameType>::const_iterator current_;
};

template <class Frame, class FrameType>
struct all_frames_iter {
  explicit all_frames_iter(const std::vector<FrameType>& frames)
      : frames_(frames) {}

  frame_iterator<Frame, FrameType> begin() {
    return frame_iterator<Frame, FrameType>(frames_);
  }

  frame_iterator<Frame, FrameType> end() {
    return frame_iterator<Frame, FrameType>(frames_, frames_.cend());
  }

 private:
  const std::vector<FrameType>& frames_;
};

template <class Frame, class FrameType>
all_frames_iter<Frame, FrameType> all_frames(
    const std::vector<FrameType>& frames) {
  return all_frames_iter<Frame, FrameType>(frames);
}

// Helper function to recursively apply a functor to a variant type or its
// subtypes
template <typename Func, typename Type>
auto variantFunc(const Type& value, const Func& func) -> decltype(auto) {
  return func(value);
}

template <typename Func, typename... Args>
auto variantFunc(const boost::variant<Args...>& variant, const Func& func)
    -> decltype(auto) {
  return folly::variant_match(
      variant, [&func](const auto& val) { return variantFunc(val, func); });
}
}
