# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_fizz_client
  handshake/FizzClientQuicHandshakeContext.cpp
  handshake/FizzClientHandshake.cpp
)

set_property(TARGET mvfst_fizz_client PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_fizz_client PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_fizz_client
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_fizz_client
  mvfst_client
  mvfst_fizz_handshake
)

target_link_libraries(
  mvfst_fizz_client PUBLIC
  mvfst_client
  mvfst_fizz_handshake
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/fizz/client/${header_dir})
endforeach()

install(
  TARGETS mvfst_fizz_client
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(test)
add_subdirectory(handshake/test)
