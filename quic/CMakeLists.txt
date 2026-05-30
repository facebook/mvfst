# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

install(FILES mvfst-config.h DESTINATION include/quic/)

# Logging backend selection. Default is glog (preserves historical behavior);
# downstream builds can opt in to folly::xlog or fully disable logging.
# Interpolated into quic-logging-config.h.in as
# `#define MVFST_LOGGING_@MVFST_LOGGING_BACKEND@ 1` and consumed from
# quic/common/MvfstLogging.h / quic/common/MvfstCheck.h.
set(MVFST_LOGGING_BACKEND "GLOG" CACHE STRING
  "Logging backend. Valid choices: GLOG, XLOG, DISABLED")
set_property(CACHE MVFST_LOGGING_BACKEND PROPERTY STRINGS GLOG XLOG DISABLED)
if(NOT MVFST_LOGGING_BACKEND MATCHES "^(GLOG|XLOG|DISABLED)$")
  message(FATAL_ERROR
    "MVFST_LOGGING_BACKEND must be one of: GLOG, XLOG, DISABLED "
    "(got '${MVFST_LOGGING_BACKEND}')")
endif()

# Generate <quic/quic-logging-config.h> for this build.
configure_file(
  quic-logging-config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/generated/quic/quic-logging-config.h)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/generated/quic/quic-logging-config.h
  DESTINATION ${INCLUDE_INSTALL_DIR}/quic/)

# Header-only INTERFACE target carrying the generated config include dir.
# Targets that include <quic/common/MvfstLogging.h> or MvfstCheck.h depend on
# this transitively via mvfst_common_mvfst_check / mvfst_common_mvfst_logging.
add_library(mvfst_logging_config INTERFACE)
target_include_directories(mvfst_logging_config INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/generated>
  $<INSTALL_INTERFACE:${INCLUDE_INSTALL_DIR}>)
install(TARGETS mvfst_logging_config EXPORT mvfst-exports)

# Many TUs include <quic/common/MvfstCheck.h> (or MvfstLogging.h) transitively
# without taking an explicit dep on mvfst_common_mvfst_check / _logging. Expose
# the generated header dir directory-wide (inherits to all add_subdirectory()s
# below) so those TUs still find <quic/quic-logging-config.h>.
include_directories(${CMAKE_CURRENT_BINARY_DIR}/generated)

# =============================================================================
# Root-level targets (manually maintained - matches BUCK structure)
# =============================================================================

# Header-only config target
mvfst_add_library(mvfst_config
  EXPORTED_DEPS
    Folly::folly_small_vector
    Folly::folly_container_f14_hash
    Folly::folly_container_heap_vector_types
)

# Header-only enum target
mvfst_add_library(mvfst_enum
  EXPORTED_DEPS
    Folly::folly_lang_assume
)

# Constants library
mvfst_add_library(mvfst_constants
  SRCS
    QuicConstants.cpp
  EXPORTED_DEPS
    mvfst_enum
    Folly::folly_chrono_clock
    Folly::folly_io_iobuf
    Folly::folly_lang_assume
)

# TLS Exception library
mvfst_add_library(mvfst_tls_exception
  SRCS
    QuicTLSExceptionFizz.cpp
  EXPORTED_DEPS
    mvfst_constants
    fizz::fizz
)

# Exception library
mvfst_add_library(mvfst_exception
  SRCS
    QuicException.cpp
  EXPORTED_DEPS
    mvfst_constants
    mvfst_tls_exception
    mvfst_common_optional
    mvfst_common_variant
    Folly::folly_range
)

install(
  FILES QuicConstants.h QuicEnum.h QuicTypealiases.h
  DESTINATION include/quic/
)

install(FILES QuicException.h DESTINATION include/quic/)
install(FILES QuicTLSException.h DESTINATION include/quic/)

# =============================================================================
# Subdirectories with granular targets
# =============================================================================

add_subdirectory(common)

# The generated common/CMakeLists.txt lists glog and
# Folly::folly_logging_logging as unconditional INTERFACE deps of
# mvfst_common_mvfst_check / mvfst_common_mvfst_logging (Buck select() can't
# be expressed losslessly there). Narrow that to the selected backend so
# XLOG / DISABLED builds don't drag in libraries they don't actually use.
if(MVFST_LOGGING_BACKEND STREQUAL "XLOG")
  set(_mvfst_check_deps
    "mvfst_logging_config;Folly::folly_logging_logging")
  set(_mvfst_logging_deps
    "mvfst_common_mvfst_check;${_mvfst_check_deps}")
  set_property(TARGET mvfst_common_mvfst_check
    PROPERTY INTERFACE_LINK_LIBRARIES "${_mvfst_check_deps}")
  set_property(TARGET mvfst_common_mvfst_logging
    PROPERTY INTERFACE_LINK_LIBRARIES "${_mvfst_logging_deps}")
elseif(MVFST_LOGGING_BACKEND STREQUAL "DISABLED")
  set_property(TARGET mvfst_common_mvfst_check
    PROPERTY INTERFACE_LINK_LIBRARIES
      "mvfst_logging_config")
  set_property(TARGET mvfst_common_mvfst_logging
    PROPERTY INTERFACE_LINK_LIBRARIES
      "mvfst_common_mvfst_check;mvfst_logging_config")
endif()
add_subdirectory(codec)
add_subdirectory(state)
add_subdirectory(flowcontrol)
add_subdirectory(handshake)
add_subdirectory(congestion_control)
add_subdirectory(loss)
add_subdirectory(logging)
add_subdirectory(observer)
add_subdirectory(priority)
add_subdirectory(happyeyeballs)
add_subdirectory(folly_utils)
add_subdirectory(datagram)
add_subdirectory(xsk)
add_subdirectory(api)
add_subdirectory(client)
add_subdirectory(server)
add_subdirectory(fizz)

if(BUILD_SAMPLES)
  add_subdirectory(samples)
endif()

if(BUILD_TOOLS)
  add_subdirectory(tools)
endif()
