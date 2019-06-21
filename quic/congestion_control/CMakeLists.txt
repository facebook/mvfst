# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_cc_algo STATIC
  CongestionControlFunctions.cpp
  CongestionControllerFactory.cpp
  Copa.cpp
  NewReno.cpp
  QuicCubic.cpp
)

target_include_directories(
  mvfst_cc_algo PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<BUILD_INTERFACE:${LIBFIZZ_INCLUDE_DIR}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_cc_algo
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_cc_algo
  mvfst_constants
  mvfst_exception
  mvfst_state_machine
  mvfst_state_functions
)

target_link_libraries(
  mvfst_cc_algo PUBLIC
  Folly::folly
  ${LIBFIZZ_LIBRARY}
  mvfst_constants
  mvfst_exception
  mvfst_state_machine
  mvfst_state_functions
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/congestion_control/${header_dir})
endforeach()

install(
  TARGETS mvfst_cc_algo
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
