# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_datagram_flow_manager
  DatagramFlowManager.cpp
)

set_property(TARGET mvfst_datagram_flow_manager PROPERTY VERSION
             ${PACKAGE_VERSION})

target_include_directories(
  mvfst_datagram_flow_manager PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_datagram_flow_manager
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_datagram_flow_manager PUBLIC
  Folly::folly
  mvfst_bufutil
  mvfst_constants
  mvfst_http_priority_queue
)

install(FILES DatagramFlowManager.h DESTINATION include/quic/datagram/)

install(
  TARGETS mvfst_datagram_flow_manager
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
