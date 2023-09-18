# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_loss
  QuicLossFunctions.cpp
)

set_property(TARGET mvfst_loss PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_loss PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_loss
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_loss
  mvfst_codec_types
  mvfst_constants
  mvfst_exception
  mvfst_flowcontrol
  mvfst_state_functions
  mvfst_state_machine
  mvfst_state_simple_frame_functions
)

target_link_libraries(
  mvfst_loss PUBLIC
  Folly::folly
  mvfst_codec_types
  mvfst_constants
  mvfst_exception
  mvfst_flowcontrol
  mvfst_state_functions
  mvfst_state_machine
  mvfst_state_simple_frame_functions
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/loss/${header_dir})
endforeach()

install(
  TARGETS mvfst_loss
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(test)
