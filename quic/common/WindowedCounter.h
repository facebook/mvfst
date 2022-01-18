/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicException.h>
#include <cstddef>
#include <type_traits>
#include <vector>

#pragma once

namespace quic {

/**
 * A moving windowed counter implementation. It works by maintaining a moving
 * window ["ts" - "window", "ts"], determined by the window size "window", and
 * sample that has the lastes timestamp "ts". It uses constant space by only
 * storing up to "threshold" number of latest sample timestamps. When the
 * number of samples within the current window exceeds "threshold", the counter
 * notifies caller via the update() API. The time complexity is O(threshold),
 * and space complexity is also O(threshold), therefore it's efficient when
 * threshold is small.
 *
 * TimeT - the type used to represent timestamp
 * TimeDeltaT - the type used to represent continuous time intervals between
 * two timestamps. Has to be the type of (a - b) if both |a| and |b| are of
 * type TimeT.
 */
template <
    typename TimeT,
    typename TimeDeltaT,
    typename = std::enable_if_t<
        std::is_arithmetic<TimeT>::value &&
        std::is_arithmetic<TimeDeltaT>::value>>
class WindowedCounter {
 public:
  /**
   * @param window The moving window size.
   * @param threshold The upper bound of number samples within the current
   * window.
   */
  WindowedCounter(TimeDeltaT window, size_t threshold)
      : window_(window), threshold_(threshold) {
    // sanity check
    if (threshold_ == 0) {
      throw QuicInternalException(
          "WindowedCounter 0 threshold", LocalErrorCode::NO_ERROR);
    }
    // If threshold is 1, then window size does not matter, uses 0 window to
    // avoid special handling such case
    if (threshold_ == 1) {
      TimeDeltaT zeroWindow{};
      window_ = zeroWindow;
    }
  }

  /**
   * Update the counter with a new sample.
   * @param sampleTs The timestamp of the new sample.
   * @return true if the number samples within the current (potentially new)
   *              window exceeds threshold, false otherwise.
   */
  bool update(TimeT sampleTs) {
    if (!insert(sampleTs)) {
      return false;
    }
    // Remove unexpired but useless sample. There should be one at most.
    if (sampleTsVec_.size() > threshold_) {
      sampleTsVec_.erase(sampleTsVec_.begin(), sampleTsVec_.begin() + 1);
    }

    return sampleTsVec_.size() == threshold_;
  }

  /**
   * Simple getter of window.
   */
  TimeDeltaT getWindow() {
    return window_;
  }

  /**
   * Simple getter of threshold
   */
  size_t getThreshold() {
    return threshold_;
  }

 private:
  /**
   * Insert the sampleTs to vector while maintaining order. Will add the
   * sampleTs to vector if it's within the current window, or latest enough to
   * move the window.
   * @param sampleTs new sample timestamp
   * @return true if the sampleTs is added, false otherwise
   */
  bool insert(TimeT sampleTs) {
    // Simple case: vector is empty
    if (sampleTsVec_.empty()) {
      sampleTsVec_.push_back(sampleTs);
      return true;
    }

    // Expired sample
    if (sampleTsVec_.back() > sampleTs &&
        sampleTsVec_.back() - sampleTs > window_) {
      return false;
    }

    // Unexpired sample, find the correct pos and insert sampleTs
    auto it = sampleTsVec_.begin();
    size_t eraseOffset = 0;
    while (it != sampleTsVec_.end()) {
      // This sample falls into the middle of the window
      if (*it >= sampleTs) {
        sampleTsVec_.insert(it, sampleTs);
        return true;
      }

      if (sampleTs > *it && sampleTs - *it > window_) {
        // New sample will move window, so remove expired ones while at it
        eraseOffset++;
      }
      it++;
    }

    // Remove unexpired samples
    sampleTsVec_.erase(
        sampleTsVec_.begin(), sampleTsVec_.begin() + eraseOffset);

    // Latest sample, push back to sampleTsVec
    sampleTsVec_.push_back(sampleTs);

    return true;
  }

  TimeDeltaT window_;
  size_t threshold_;
  /**
   * An ordered vector of samples in ascending order.
   */
  std::vector<TimeT> sampleTsVec_;
};

} // namespace quic
