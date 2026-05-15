/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/LinuxKernelVersion.h>

#include <gtest/gtest.h>

using namespace quic;
using quic::detail::parseLinuxKernelRelease;

class LinuxKernelVersionTest : public ::testing::Test {};

TEST_F(LinuxKernelVersionTest, ParseVanillaRelease) {
  auto v = parseLinuxKernelRelease("6.4.0");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(std::make_pair(6, 4), *v);
}

TEST_F(LinuxKernelVersionTest, ParseDistroSuffix) {
  auto v = parseLinuxKernelRelease("6.9.12-arch1-1");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(std::make_pair(6, 9), *v);
}

TEST_F(LinuxKernelVersionTest, ParseComplexSuffix) {
  auto v = parseLinuxKernelRelease("6.16.1-0_custom7_hardened_0_a1b2c3d4e5f6");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(std::make_pair(6, 16), *v);
}

TEST_F(LinuxKernelVersionTest, ParseReleaseCandidate) {
  auto v = parseLinuxKernelRelease("6.4-rc7");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(std::make_pair(6, 4), *v);
}

TEST_F(LinuxKernelVersionTest, ParseTwoDigitMinor) {
  auto v = parseLinuxKernelRelease("5.15.0-custom");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(std::make_pair(5, 15), *v);
}

TEST_F(LinuxKernelVersionTest, ParseEmpty) {
  EXPECT_FALSE(parseLinuxKernelRelease("").has_value());
}

TEST_F(LinuxKernelVersionTest, ParseNullptr) {
  EXPECT_FALSE(parseLinuxKernelRelease(nullptr).has_value());
}

TEST_F(LinuxKernelVersionTest, ParseGarbage) {
  EXPECT_FALSE(parseLinuxKernelRelease("garbage").has_value());
}

TEST_F(LinuxKernelVersionTest, ParseMajorOnly) {
  EXPECT_FALSE(parseLinuxKernelRelease("6").has_value());
}

TEST_F(LinuxKernelVersionTest, ParseTrailingDot) {
  EXPECT_FALSE(parseLinuxKernelRelease("6.").has_value());
}

TEST_F(LinuxKernelVersionTest, ParseNonNumericMinor) {
  EXPECT_FALSE(parseLinuxKernelRelease("6.x").has_value());
}

TEST_F(LinuxKernelVersionTest, ParseLeadingDot) {
  EXPECT_FALSE(parseLinuxKernelRelease(".6").has_value());
}

TEST_F(LinuxKernelVersionTest, AtLeastEqualMajorEqualMinor) {
  // Sanity-check the comparison logic via a manually-constructed test path:
  // we cannot mock getLinuxKernelVersion() since it caches, so we verify the
  // version we read back is internally consistent.
  auto version = getLinuxKernelVersion();
#ifdef __linux__
  ASSERT_TRUE(version.has_value());
  EXPECT_TRUE(isLinuxKernelAtLeast({version->first, version->second}));
  EXPECT_TRUE(isLinuxKernelAtLeast({version->first, 0}));
  EXPECT_TRUE(isLinuxKernelAtLeast({0, 0}));
  EXPECT_FALSE(isLinuxKernelAtLeast({version->first + 1, 0}));
  EXPECT_FALSE(isLinuxKernelAtLeast({version->first, version->second + 1}));
#else
  EXPECT_FALSE(version.has_value());
  EXPECT_FALSE(isLinuxKernelAtLeast({0, 0}));
#endif
}
