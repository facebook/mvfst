# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# - Try to find Libevent
# Once done, this will define
#
# LIBEVENT_FOUND - system has Libevent
# LIBEVENT_INCLUDE_DIRS - the Libevent include directories
# LIBEVENT_LIBRARIES - link these to use Libevent

include(FindPackageHandleStandardArgs)

find_library(LIBEVENT_LIBRARY event
  PATHS ${LIBEVENT_LIBRARYDIR})

find_path(LIBEVENT_INCLUDE_DIR event.h
  PATHS ${LIBEVENT_INCLUDEDIR})

find_package_handle_standard_args(libevent DEFAULT_MSG
  LIBEVENT_LIBRARY
  LIBEVENT_INCLUDE_DIR)

mark_as_advanced(
  LIBEVENT_LIBRARY
  LIBEVENT_INCLUDE_DIR)

set(LIBEVENT_LIBRARIES ${LIBEVENT_LIBRARY})
set(LIBEVENT_INCLUDE_DIRS ${LIBEVENT_INCLUDE_DIR})
