# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

add_executable(tperf tperf.cpp TperfQLogger.cpp PacingObserver.cpp)

add_library(
  tperf_pacing_observer STATIC
  PacingObserver.cpp
)

target_compile_options(
  tperf
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_include_directories(tperf PRIVATE
  ${LIBGMOCK_INCLUDE_DIR}
  ${LIBGTEST_INCLUDE_DIR}
)

add_dependencies(tperf googletest)

target_link_libraries(
  tperf PUBLIC
  Folly::folly
  fizz::fizz
  mvfst_test_utils
  ${GFLAGS_LIBRARIES}
  ${LIBGMOCK_LIBRARIES}
  ${LIBGTEST_LIBRARIES}
)
