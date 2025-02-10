# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_round_robin
  RoundRobin.cpp
)

target_include_directories(
  mvfst_round_robin PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_round_robin
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_round_robin PUBLIC
  Folly::folly
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/priority/${header_dir})
endforeach()

install(
  TARGETS mvfst_round_robin
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(test)
