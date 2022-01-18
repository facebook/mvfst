/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/init/Init.h>

#include <folly/Portability.h>
#include <folly/portability/GFlags.h>
#include <folly/portability/GTest.h>

/*
 * This is the recommended main function for all tests.
 * The Makefile links it into all of the test programs so that tests do not need
 * to - and indeed should typically not - define their own main() functions
 */
FOLLY_ATTR_WEAK int main(int argc, char** argv);

int main(int argc, char** argv) {
#if FOLLY_HAVE_LIBGFLAGS
  // Enable glog logging to stderr by default.
  gflags::SetCommandLineOptionWithMode(
      "logtostderr", "1", gflags::SET_FLAGS_DEFAULT);
#endif

  ::testing::InitGoogleTest(&argc, argv);
  folly::Init init(&argc, &argv);

  return RUN_ALL_TESTS();
}
