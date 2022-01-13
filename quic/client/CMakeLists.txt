# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_client STATIC
  QuicClientTransport.cpp
  QuicClientAsyncTransport.cpp
  handshake/ClientHandshake.cpp
  state/ClientStateMachine.cpp
  connector/QuicConnector.cpp
)

target_include_directories(
  mvfst_client PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_client
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_client
  mvfst_bufutil
  mvfst_flowcontrol
  mvfst_happyeyeballs
  mvfst_loss
  mvfst_qlogger
  mvfst_socketutil
  mvfst_state_ack_handler
  mvfst_state_datagram_handler
  mvfst_state_pacing_functions
  mvfst_transport
)

target_link_libraries(
  mvfst_client PUBLIC
  Folly::folly
  mvfst_flowcontrol
  mvfst_happyeyeballs
  mvfst_loss
  mvfst_qlogger
  mvfst_socketutil
  mvfst_state_ack_handler
  mvfst_state_datagram_handler
  mvfst_state_pacing_functions
  mvfst_transport
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/client/${header_dir})
endforeach()

install(
  TARGETS mvfst_client
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
