# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

install(FILES mvfst-config.h DESTINATION include/quic/)

add_library(
  mvfst_constants
  QuicConstants.cpp
)

set_property(TARGET mvfst_constants PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_constants PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
  PRIVATE
  ${Boost_INCLUDE_DIR}
)

target_compile_options(
  mvfst_constants
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_constants PUBLIC
  Folly::folly
  ${Boost_LIBRARIES}
)

install(FILES QuicConstants.h DESTINATION include/quic/)

install(
  TARGETS mvfst_constants
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_library(
  mvfst_exception
  QuicException.cpp
)

set_property(TARGET mvfst_exception PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_exception PUBLIC
  $<BUILD_INTERFACE:${LIBFIZZ_INCLUDE_DIR}>
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_exception
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_exception PUBLIC
  Folly::folly
  ${LIBFIZZ_LIBRARY}
)

install(FILES QuicException.h DESTINATION include/quic/)

install(
  TARGETS mvfst_exception
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
add_subdirectory(api)
add_subdirectory(client)
add_subdirectory(codec)
add_subdirectory(common)
add_subdirectory(congestion_control)
add_subdirectory(dsr)
add_subdirectory(fizz)
add_subdirectory(flowcontrol)
add_subdirectory(handshake)
add_subdirectory(happyeyeballs)
add_subdirectory(logging)
add_subdirectory(loss)
add_subdirectory(observer)
add_subdirectory(priority)
add_subdirectory(samples)
add_subdirectory(server)
add_subdirectory(state)
add_subdirectory(tools)
add_subdirectory(xsk)
