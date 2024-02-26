# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_xsk
  packet_utils.cpp
  xsk_lib.cpp
  BaseXskContainer.cpp
  HashingXskContainer.cpp
  ThreadLocalXskContainer.cpp
  XskSender.cpp
)

set_property(TARGET mvfst_xsk PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_xsk PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_link_libraries(
  mvfst_xsk PUBLIC
  Folly::folly
)

target_compile_options(
  mvfst_xsk
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/dsr/${header_dir})
endforeach()

install(
  TARGETS mvfst_xsk
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
