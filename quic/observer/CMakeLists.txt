# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_observer
  SocketObserverInterface.cpp
)

set_property(TARGET mvfst_observer PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_observer PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_observer
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_observer
  mvfst_constants
  mvfst_exception
  mvfst_state_ack_handler
  mvfst_state_machine
)

target_link_libraries(
  mvfst_observer PUBLIC
  Folly::folly
  mvfst_constants
  mvfst_exception
  mvfst_state_ack_handler
  mvfst_state_machine
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
  install(FILES ${header} DESTINATION include/quic/observer/${header_dir})
endforeach()

install(
  TARGETS mvfst_observer
  EXPORT mvfst-exports
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
