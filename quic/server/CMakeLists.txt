# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_server STATIC
  QuicServer.cpp
  QuicServerPacketRouter.cpp
  QuicServerTransport.cpp
  QuicServerWorker.cpp
  handshake/ServerHandshake.cpp
  handshake/AppToken.cpp
  handshake/DefaultAppTokenValidator.cpp
  handshake/StatelessResetGenerator.cpp
  state/ServerStateMachine.cpp
)

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
  mvfst_constants
  mvfst_codec
  mvfst_codec_types
  mvfst_handshake
  mvfst_transport
)

target_link_libraries(
  mvfst_server PUBLIC
  Folly::folly
  ${LIBFIZZ_LIBRARY}
  mvfst_constants
  mvfst_codec
  mvfst_codec_types
  mvfst_handshake
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
  install(FILES ${header} DESTINATION include/quic/server/${header_dir})
endforeach()

install(
  TARGETS mvfst_server
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
add_subdirectory(handshake/test)
