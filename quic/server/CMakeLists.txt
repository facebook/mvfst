# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_server_state
  handshake/AppToken.cpp
  handshake/ServerHandshake.cpp
  handshake/StatelessResetGenerator.cpp
  handshake/TokenGenerator.cpp
  state/ServerStateMachine.cpp)

set_property(TARGET mvfst_server_state PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_server_state PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<BUILD_INTERFACE:${LIBFIZZ_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_server_state
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_server_state
  mvfst_buf_accessor
  mvfst_cc_algo
  mvfst_constants
  mvfst_codec
  mvfst_codec_types
  mvfst_dsr_frontend
  mvfst_fizz_handshake
  mvfst_qlogger
  mvfst_state_ack_handler
)


add_library(
  mvfst_server
  QuicServer.cpp
  QuicServerBackend.cpp
  QuicServerPacketRouter.cpp
  QuicServerTransport.cpp
  QuicServerWorker.cpp
  SlidingWindowRateLimiter.cpp
  handshake/DefaultAppTokenValidator.cpp
  handshake/TokenGenerator.cpp

  # Fizz specific parts, will be split in its own lib eventually.
  ../fizz/server/handshake/AppToken.cpp
  ../fizz/server/handshake/FizzServerQuicHandshakeContext.cpp
  ../fizz/server/handshake/FizzServerHandshake.cpp
)

set_property(TARGET mvfst_server PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_server PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<BUILD_INTERFACE:${LIBFIZZ_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_server
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_server
  mvfst_buf_accessor
  mvfst_cc_algo
  mvfst_constants
  mvfst_codec
  mvfst_codec_types
  mvfst_dsr_frontend
  mvfst_fizz_handshake
  mvfst_qlogger
  mvfst_server_state
  mvfst_state_ack_handler
  mvfst_state_datagram_handler
  mvfst_transport
  mvfst_transport_knobs
  mvfst_transport_settings_functions
)

add_library(
  mvfst_server_async_tran
  async_tran/QuicAsyncTransportAcceptor.cpp
  async_tran/QuicAsyncTransportServer.cpp
  async_tran/QuicServerAsyncTransport.cpp
  )

set_property(TARGET mvfst_server_async_tran PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_server_async_tran PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<BUILD_INTERFACE:${LIBFIZZ_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_server_async_tran
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_server_async_tran
  mvfst_buf_accessor
  mvfst_cc_algo
  mvfst_constants
  mvfst_codec
  mvfst_codec_types
  mvfst_dsr_frontend
  mvfst_fizz_handshake
  mvfst_qlogger
  mvfst_state_ack_handler
)

target_link_libraries(
  mvfst_server_state PUBLIC
  Folly::folly
  ${LIBFIZZ_LIBRARY}
  mvfst_buf_accessor
  mvfst_constants
  mvfst_codec
  mvfst_codec_types
  mvfst_dsr_frontend
  mvfst_fizz_handshake
  mvfst_qlogger
  mvfst_state_ack_handler
  mvfst_transport
  mvfst_transport_knobs
)

target_link_libraries(
  mvfst_server PUBLIC
  Folly::folly
  ${LIBFIZZ_LIBRARY}
  mvfst_buf_accessor
  mvfst_constants
  mvfst_codec
  mvfst_codec_types
  mvfst_dsr_frontend
  mvfst_fizz_handshake
  mvfst_qlogger
  mvfst_server_state
  mvfst_state_ack_handler
  mvfst_state_datagram_handler
  mvfst_transport
  mvfst_transport_knobs
  mvfst_transport_settings_functions
)

target_link_libraries(
  mvfst_server_async_tran PUBLIC
  Folly::folly
  ${LIBFIZZ_LIBRARY}
  mvfst_server
  mvfst_buf_accessor
  mvfst_constants
  mvfst_codec
  mvfst_codec_types
  mvfst_dsr_frontend
  mvfst_fizz_handshake
  mvfst_qlogger
  mvfst_server_state
  mvfst_state_ack_handler
  mvfst_state_datagram_handler
  mvfst_transport
  mvfst_transport_knobs
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/server/${header_dir})
endforeach()

install(
  TARGETS mvfst_server
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  TARGETS mvfst_server_state
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  TARGETS mvfst_server_async_tran
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(test)
add_subdirectory(handshake/test)
