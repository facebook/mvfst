# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

install(FILES mvfst-config.h DESTINATION include/quic/)

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
