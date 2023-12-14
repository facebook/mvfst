# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_async_udp_socket
  QuicAsyncUDPSocket.cpp
  QuicAsyncUDPSocketImpl.cpp
  FollyQuicAsyncUDPSocket.cpp
)

set_property(TARGET mvfst_async_udp_socket PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_async_udp_socket PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_async_udp_socket
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_async_udp_socket PUBLIC
  Folly::folly
  mvfst_events
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/api/${header_dir})
endforeach()

install(
  TARGETS mvfst_async_udp_socket
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
