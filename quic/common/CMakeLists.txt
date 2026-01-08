# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_buf_accessor
  BufAccessor.cpp
)

set_property(TARGET mvfst_buf_accessor PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_buf_accessor PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_buf_accessor
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_buf_accessor PUBLIC
  Folly::folly
)

add_library(
  mvfst_looper
  events/HighResQuicTimer.cpp
)

set_property(TARGET mvfst_looper PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_looper PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_looper
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_looper PUBLIC
  Folly::folly
)

add_library(
  mvfst_bufutil
  BufUtil.cpp
  ChainedByteRange.cpp
)

set_property(TARGET mvfst_bufutil PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_bufutil PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_bufutil
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_bufutil PUBLIC
  Folly::folly
)

add_library(
  mvfst_string_utils
  StringUtils.cpp
)

set_property(TARGET mvfst_string_utils PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_string_utils PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_string_utils
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_string_utils PUBLIC
  mvfst_constants
  mvfst_exception
)

add_library(
  mvfst_transport_knobs
  TransportKnobs.cpp
)

set_property(TARGET mvfst_transport_knobs PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_transport_knobs PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_transport_knobs
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_transport_knobs PUBLIC
  mvfst_constants
  Folly::folly
)

add_library(
  mvfst_contiguous_cursor
  ContiguousCursor.cpp
)

set_property(TARGET mvfst_contiguous_cursor PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_contiguous_cursor PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_contiguous_cursor
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_contiguous_cursor PUBLIC
  Folly::folly
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h *.hpp
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/common/${header_dir})
endforeach()

install(
  TARGETS mvfst_looper
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  TARGETS mvfst_buf_accessor
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  TARGETS mvfst_bufutil
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  TARGETS mvfst_string_utils
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  TARGETS mvfst_transport_knobs
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(
  TARGETS mvfst_contiguous_cursor
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(events)
add_subdirectory(udpsocket)
add_subdirectory(test)
