/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/IntervalSet.h>

#include <gtest/gtest.h>

using namespace std;
using namespace quic;

TEST(IntervalSet, empty) {
  IntervalSet<int> set;
  auto originalVersion = set.insertVersion();
  set.insert(1, 2);
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
  EXPECT_GT(set.insertVersion(), originalVersion);
}

TEST(IntervalSet, insertAtFront) {
  IntervalSet<int> set;
  auto version1 = set.insertVersion();
  set.insert(4, 5);
  auto version2 = set.insertVersion();
  set.insert(1, 2);
  auto version3 = set.insertVersion();
  auto interval = set.back();
  EXPECT_EQ(interval, Interval<int>(4, 5));
  set.pop_back();
  interval = set.back();
  EXPECT_EQ(interval, Interval<int>(1, 2));
  set.pop_back();
  EXPECT_TRUE(set.empty());
  EXPECT_GT(version2, version1);
  EXPECT_GT(version3, version2);
}

TEST(IntervalSet, insertAtBack) {
  IntervalSet<int> set;
  set.insert(1, 2);
  set.insert(4, 4);
  auto interval = set.back();
  EXPECT_EQ(interval, Interval<int>(4, 4));
  set.pop_back();
  interval = set.back();
  EXPECT_EQ(interval, Interval<int>(1, 2));
  set.pop_back();
  EXPECT_TRUE(set.empty());
}

TEST(IntervalSet, insertInTheMiddle) {
  IntervalSet<int> set;
  set.insert(1, 2);
  set.insert(7, 8);

  auto version1 = set.insertVersion();

  // Insert at the front but should be merged with first element
  set.insert(4, 5);

  auto version2 = set.insertVersion();
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
  EXPECT_EQ(*++itr, Interval<int>(4, 5));
  EXPECT_EQ(*++itr, Interval<int>(7, 8));
  EXPECT_TRUE(++itr == set.cend());
  EXPECT_GT(version2, version1);
}

TEST(IntervalSet, insertAtFrontWithMerge) {
  IntervalSet<int> set;
  set.insert(3, 5);
  set.insert(7, 8);
  auto version1 = set.insertVersion();

  // Insert at the front but should be merged with first element
  set.insert(1, 4);
  auto version2 = set.insertVersion();
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 5));
  EXPECT_EQ(*++itr, Interval<int>(7, 8));
  EXPECT_TRUE(++itr == set.cend());
  EXPECT_GT(version2, version1);
}

TEST(IntervalSet, insertAtBackWithMerge) {
  IntervalSet<int> set;
  set.insert(1, 2);
  set.insert(5, 8);

  // Insert at the front but should be merged with first element
  set.insert(6, 9);
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
  EXPECT_EQ(*++itr, Interval<int>(5, 9));
  EXPECT_TRUE(++itr == set.cend());
}

TEST(IntervalSet, insertInTheMiddleWithMerge) {
  IntervalSet<int> set;
  set.insert(1, 2);
  set.insert(5, 6);
  set.insert(8, 9);
  auto version1 = set.insertVersion();

  set.insert(4, 6);
  auto version2 = set.insertVersion();
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
  EXPECT_EQ(*++itr, Interval<int>(4, 6));
  EXPECT_EQ(*++itr, Interval<int>(8, 9));
  EXPECT_TRUE(++itr == set.cend());
  EXPECT_GT(version2, version1);
}

TEST(IntervalSet, insertWithMultipleMerge) {
  IntervalSet<int> set;
  set.insert(1, 2);
  set.insert(4, 5);
  set.insert(7, 8);
  set.insert(10, 12);
  set.insert(14, 15);

  // Insert with merge
  set.insert(4, 9);
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
  EXPECT_EQ(*++itr, Interval<int>(4, 12));
  EXPECT_EQ(*++itr, Interval<int>(14, 15));
  EXPECT_TRUE(++itr == set.cend());
}

TEST(IntervalSet, insertWithMergeAtEdge) {
  IntervalSet<int> set;
  set.insert(1, 2);
  set.insert(4, 7);

  // Merge at edge
  set.insert(3, 3);
  auto interval = set.front();
  EXPECT_EQ(interval, Interval<int>(1, 7));
  set.pop_back();
  EXPECT_TRUE(set.empty());
}

TEST(IntervalSet, insertBoundTooLarge) {
  IntervalSet<uint32_t, 10> set;
  EXPECT_THROW(
      set.insert(0, std::numeric_limits<uint32_t>::max() - 9),
      std::invalid_argument);
  set.insert(0, std::numeric_limits<uint32_t>::max() - 10);
}

TEST(IntervalSet, insertVersionDoesNotChange) {
  IntervalSet<int> set;
  set.insert(1, 4);
  set.insert(6, 8);
  set.insert(9, 10);

  auto version1 = set.insertVersion();

  // Merge at edge
  set.insert(3, 4);
  auto version2 = set.insertVersion();
  EXPECT_EQ(version2, version1);
}

TEST(IntervalSet, withdrawBeforeFront) {
  IntervalSet<int> set;
  set.insert(4, 5);
  set.withdraw({1, 2});
  EXPECT_EQ(1, set.size());
  auto interval = set.front();
  EXPECT_EQ(interval, Interval<int>(4, 5));
}

TEST(IntervalSet, withdrawAfterBack) {
  IntervalSet<int> set;
  set.insert(1, 2);
  set.withdraw({4, 5});
  EXPECT_EQ(1, set.size());
  auto interval = set.front();
  EXPECT_EQ(interval, Interval<int>(1, 2));
}

TEST(IntervalSet, withdrawMiddleNoIntersection) {
  IntervalSet<int> set;
  set.insert(1, 2);
  set.insert(7, 8);
  set.withdraw({4, 5});
  EXPECT_EQ(2, set.size());
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
  EXPECT_EQ(*++itr, Interval<int>(7, 8));
}

TEST(IntervalSet, withdrawMiddleLeftIntersection1) {
  IntervalSet<int> set;
  set.insert(1, 3);
  set.insert(7, 8);
  set.withdraw({3, 5});
  EXPECT_EQ(2, set.size());
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
  EXPECT_EQ(*++itr, Interval<int>(7, 8));
}

TEST(IntervalSet, withdrawMiddleLeftIntersection2) {
  IntervalSet<int> set;
  set.insert(2, 3);
  set.insert(7, 8);
  set.withdraw({1, 5});
  EXPECT_EQ(1, set.size());
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(7, 8));
}

TEST(IntervalSet, withdrawMiddleRightIntersection1) {
  IntervalSet<int> set;
  set.insert(1, 2);
  set.insert(5, 8);
  set.withdraw({4, 6});
  EXPECT_EQ(2, set.size());
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
  EXPECT_EQ(*++itr, Interval<int>(7, 8));
}

TEST(IntervalSet, withdrawMiddleRightIntersection2) {
  IntervalSet<int> set;
  set.insert(1, 2);
  set.insert(5, 6);
  set.withdraw({4, 6});
  EXPECT_EQ(1, set.size());
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
}

TEST(IntervalSet, withdrawMiddleBothIntersection1) {
  IntervalSet<int> set;
  set.insert(1, 3);
  set.insert(5, 8);
  set.withdraw({3, 6});
  EXPECT_EQ(2, set.size());
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
  EXPECT_EQ(*++itr, Interval<int>(7, 8));
}

TEST(IntervalSet, withdrawMiddleBothIntersection2) {
  IntervalSet<int> set;
  set.insert(1, 3);
  set.insert(5, 8);
  set.withdraw({1, 10});
  EXPECT_EQ(0, set.size());
}

TEST(IntervalSet, withdrawMultipleIntersection) {
  IntervalSet<int> set;
  set.insert(1, 3);
  set.insert(7, 8);
  set.insert(10, 12);
  set.insert(14, 18);
  set.withdraw({3, 18});
  EXPECT_EQ(1, set.size());
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 2));
}

TEST(IntervalSet, withdrawSubinterval) {
  IntervalSet<int> set;
  set.insert(1, 5);
  set.withdraw({2, 2});
  EXPECT_EQ(2, set.size());
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(1, 1));
  EXPECT_EQ(*++itr, Interval<int>(3, 5));
}

TEST(IntervalSet, withdrawSubintervalOnEdge) {
  IntervalSet<int> set;
  set.insert(1, 5);
  set.withdraw({1, 1});
  EXPECT_EQ(1, set.size());
  auto itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(2, 5));
  set.withdraw({4, 5});
  EXPECT_EQ(1, set.size());
  itr = set.cbegin();
  EXPECT_EQ(*itr, Interval<int>(2, 3));
}

TEST(IntervalSet, withdrawWithOverflow) {
  IntervalSet<int> set;
  set.insert(0, 5);
  set.withdraw({0, 2});
  EXPECT_EQ(1, set.size());
  auto interval = set.front();
  EXPECT_EQ(interval, Interval<int>(3, 5));
}

TEST(IntervalSet, equalityComparatorEqual) {
  IntervalSet<int> set1;
  set1.insert(0, 5);

  IntervalSet<int> set2;
  set2.insert(0, 5);

  EXPECT_EQ(set1, set2);
  EXPECT_TRUE(set1 == set2);
  EXPECT_FALSE(set1 != set2);
}

TEST(IntervalSet, equalityComparatorEqualMultiInterval) {
  IntervalSet<int> set1;
  set1.insert(0, 5);
  set1.insert(6, 10);

  IntervalSet<int> set2;
  set2.insert(0, 5);
  set2.insert(6, 10);

  EXPECT_EQ(set1, set2);
  EXPECT_TRUE(set1 == set2);
  EXPECT_FALSE(set1 != set2);
}

TEST(IntervalSet, equalityComparatorNotEqualEmpty) {
  IntervalSet<int> set1;
  set1.insert(0, 5);

  IntervalSet<int> set2;

  EXPECT_NE(set1, set2);
  EXPECT_FALSE(set1 == set2);
  EXPECT_TRUE(set1 != set2);
}

TEST(IntervalSet, equalityComparatorNotEqualDiffInterval) {
  IntervalSet<int> set1;
  set1.insert(0, 5);

  IntervalSet<int> set2;
  set2.insert(0, 6);

  EXPECT_NE(set1, set2);
  EXPECT_FALSE(set1 == set2);
  EXPECT_TRUE(set1 != set2);
}

TEST(IntervalSet, equalityComparatorNotEqualDiffIntervals1) {
  IntervalSet<int> set1;
  set1.insert(0, 5);

  IntervalSet<int> set2;
  set2.insert(0, 5);
  set2.insert(6, 10);

  EXPECT_NE(set1, set2);
  EXPECT_FALSE(set1 == set2);
  EXPECT_TRUE(set1 != set2);
}

TEST(IntervalSet, equalityComparatorNotEqualDiffIntervals2) {
  IntervalSet<int> set1;
  set1.insert(0, 5);
  set1.insert(6, 11);

  IntervalSet<int> set2;
  set2.insert(0, 5);
  set2.insert(6, 10);

  EXPECT_NE(set1, set2);
  EXPECT_FALSE(set1 == set2);
  EXPECT_TRUE(set1 != set2);
}
