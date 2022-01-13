# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_qlogger STATIC
  BaseQLogger.cpp
  FileQLogger.cpp
  QLogger.cpp
  QLoggerConstants.cpp
  QLoggerTypes.cpp
)

target_include_directories(
  mvfst_qlogger PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_qlogger
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_qlogger
  mvfst_codec_types
  mvfst_state_machine
)

target_link_libraries(
  mvfst_qlogger PUBLIC
  Folly::folly
  mvfst_codec_types
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/logging/${header_dir})
endforeach()

install(
  TARGETS mvfst_qlogger
  EXPORT mvfst-exports
  DESTINATION lib
)

add_subdirectory(test)
