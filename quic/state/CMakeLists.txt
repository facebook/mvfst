# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_state_transport_settings
  TransportSettings.h
)

target_include_directories(
  mvfst_state_transport_settings PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_transport_settings
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_state_transport_settings
  mvfst_constants
)

target_link_libraries(
  mvfst_state_transport_settings PUBLIC
  Folly::folly
  mvfst_constants
)

add_library(
  mvfst_state_ack_states
  AckStates.h
)

target_include_directories(
  mvfst_state_ack_states PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_ack_states
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_state_ack_states
  mvfst_codec_types
)

target_link_libraries(
  mvfst_state_ack_states PUBLIC
  Folly::folly
  mvfst_codec_types
)

add_library(
  mvfst_state_machine
  QuicStreamManager.cpp
  QuicStreamUtilities.cpp
  StateData.cpp
)

target_include_directories(
  mvfst_state_machine PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_machine
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_state_machine
  mvfst_constants
  mvfst_codec
  mvfst_codec_types
  mvfst_handshake
  mvfst_state_ack_states
  mvfst_state_stats_callback
  mvfst_state_transport_settings
)

target_link_libraries(
  mvfst_state_machine PUBLIC
  Folly::folly
  ${BOOST_LIBRARIES}
  mvfst_constants
  mvfst_codec
  mvfst_codec_types
  mvfst_handshake
  mvfst_state_ack_states
  mvfst_state_stats_callback
  mvfst_state_transport_settings
)

add_library(
  mvfst_state_ack_handler
  AckHandlers.cpp
)

target_include_directories(
  mvfst_state_ack_handler PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_ack_handler
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_state_ack_handler
  mvfst_constants
  mvfst_codec_types
  mvfst_logging
  mvfst_loss
  mvfst_state_functions
  mvfst_state_machine
)

target_link_libraries(
  mvfst_state_ack_handler PUBLIC
  Folly::folly
  mvfst_constants
  mvfst_codec_types
  mvfst_logging
  mvfst_loss
  mvfst_state_functions
  mvfst_state_machine
)

# stream functions
add_library(
  mvfst_state_stream_functions
  QuicStreamFunctions.cpp
)

target_include_directories(
  mvfst_state_stream_functions PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_stream_functions
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_state_stream_functions
  mvfst_codec
  mvfst_codec_types
  mvfst_logging
  mvfst_state_machine
)

target_link_libraries(
  mvfst_state_stream_functions PUBLIC
  Folly::folly
  mvfst_codec
  mvfst_codec_types
  mvfst_logging
  mvfst_state_machine
)


# state functions
add_library(
  mvfst_state_functions
  QuicStateFunctions.cpp
)

target_include_directories(
  mvfst_state_functions PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_functions
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_state_functions
  mvfst_codec_pktbuilder
  mvfst_codec_types
  mvfst_logging
  mvfst_state_machine
  mvfst_state_stream
)

target_link_libraries(
  mvfst_state_functions PUBLIC
  Folly::folly
  mvfst_codec_pktbuilder
  mvfst_codec_types
  mvfst_logging
  mvfst_state_machine
  mvfst_state_stream
)

# pacing function
add_library(
  mvfst_state_pacing_functions
  QuicPacingFunctions.cpp
)

target_include_directories(
  mvfst_state_pacing_functions PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_pacing_functions
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_state_pacing_functions
  mvfst_state_machine
)

target_link_libraries(
  mvfst_state_pacing_functions PUBLIC
  Folly::folly
  mvfst_state_machine
)


# stats callback
add_library(
  mvfst_state_stats_callback
  QuicTransportStatsCallback.h
)

target_include_directories(
  mvfst_state_stats_callback PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_stats_callback
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_state_stats_callback PUBLIC
  Folly::folly
)

# simple frame function
add_library(
  mvfst_state_simple_frame_functions
  SimpleFrameFunctions.cpp
)

target_include_directories(
  mvfst_state_simple_frame_functions PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_simple_frame_functions
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_state_simple_frame_functions
  mvfst_state_qpr_functions
  mvfst_state_functions
  mvfst_state_machine
  mvfst_codec_types
)

target_link_libraries(
  mvfst_state_simple_frame_functions PUBLIC
  Folly::folly
  mvfst_state_qpr_functions
  mvfst_state_functions
  mvfst_state_machine
  mvfst_codec_types
)


# qpr function
add_library(
  mvfst_state_qpr_functions
  QPRFunctions.cpp
)

target_include_directories(
  mvfst_state_qpr_functions PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_qpr_functions
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_state_qpr_functions
  mvfst_state_machine
  mvfst_state_stream_functions
  mvfst_codec_types
  mvfst_flowcontrol
)

target_link_libraries(
  mvfst_state_qpr_functions PUBLIC
  Folly::folly
  mvfst_state_machine
  mvfst_state_stream_functions
  mvfst_codec_types
  mvfst_flowcontrol
)


add_library(
  mvfst_state_stream STATIC
  stream/StreamStateFunctions.cpp
)

target_include_directories(
  mvfst_state_stream PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_state_stream
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_state_stream
  mvfst_codec_types
  mvfst_exception
  mvfst_flowcontrol
  mvfst_state_machine
  mvfst_state_stream_functions
)

target_link_libraries(
  mvfst_state_stream PUBLIC
  Folly::folly
  mvfst_codec_types
  mvfst_exception
  mvfst_flowcontrol
  mvfst_state_machine
  mvfst_state_stream_functions
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX tests/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/state/${header_dir})
endforeach()

install(
  TARGETS mvfst_state_transport_settings
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_state_ack_states
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_state_machine
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_state_ack_handler
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_state_stream_functions
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_state_pacing_functions
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_state_functions
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_state_stats_callback
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_state_simple_frame_functions
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_state_qpr_functions
  EXPORT mvfst-exports
  DESTINATION lib
)

install(
  TARGETS mvfst_state_stream
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
add_subdirectory(stream/test)
