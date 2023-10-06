# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_batch_writer
  QuicBatchWriter.cpp
  QuicBatchWriterFactory.cpp
  QuicGsoBatchWriters.cpp
)

set_property(TARGET mvfst_batch_writer PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_batch_writer PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_batch_writer
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_batch_writer
  mvfst_async_udp_socket_wrapper
  mvfst_events
  mvfst_constants
  mvfst_state_machine
)

target_link_libraries(
  mvfst_batch_writer PUBLIC
  Folly::folly
  mvfst_async_udp_socket_wrapper
  mvfst_events
  mvfst_constants
  mvfst_state_machine
)

add_library(
  mvfst_transport
  IoBufQuicBatch.cpp
  QuicPacketScheduler.cpp
  QuicStreamAsyncTransport.cpp
  QuicTransportBase.cpp
  QuicTransportFunctions.cpp
)

set_property(TARGET mvfst_transport PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_transport PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_transport
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_transport
  mvfst_async_udp_socket_wrapper
  mvfst_batch_writer
  mvfst_buf_accessor
  mvfst_bufutil
  mvfst_cc_algo
  mvfst_codec
  mvfst_codec_pktbuilder
  mvfst_codec_pktrebuilder
  mvfst_codec_types
  mvfst_constants
  mvfst_events
  mvfst_exception
  mvfst_flowcontrol
  mvfst_happyeyeballs
  mvfst_looper
  mvfst_loss
  mvfst_observer
  mvfst_qlogger
  mvfst_socketutil
  mvfst_state_ack_handler
  mvfst_state_datagram_handler
  mvfst_state_functions
  mvfst_state_machine
  mvfst_state_pacing_functions
  mvfst_state_simple_frame_functions
  mvfst_state_stream
  mvfst_state_stream_functions
)

target_link_libraries(
  mvfst_transport PUBLIC
  Folly::folly
  mvfst_batch_writer
  mvfst_buf_accessor
  mvfst_bufutil
  mvfst_cc_algo
  mvfst_codec
  mvfst_codec_pktbuilder
  mvfst_codec_pktrebuilder
  mvfst_codec_types
  mvfst_constants
  mvfst_events
  mvfst_exception
  mvfst_flowcontrol
  mvfst_happyeyeballs
  mvfst_looper
  mvfst_loss
  mvfst_observer
  mvfst_qlogger
  mvfst_socketutil
  mvfst_state_ack_handler
  mvfst_state_datagram_handler
  mvfst_state_functions
  mvfst_state_machine
  mvfst_state_pacing_functions
  mvfst_state_simple_frame_functions
  mvfst_state_stream
  mvfst_state_stream_functions
  PRIVATE
  ${BOOST_LIBRARIES}
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
  TARGETS mvfst_transport
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  TARGETS mvfst_batch_writer
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(test)
