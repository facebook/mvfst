# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

add_library(
  mvfst_cc_algo
  Bandwidth.cpp
  Bbr.cpp
  BbrBandwidthSampler.cpp
  BbrRttSampler.cpp
  BbrTesting.cpp
  Bbr2.cpp
  CongestionControlFunctions.cpp
  CongestionControllerFactory.cpp
  Copa.cpp
  Copa2.cpp
  NewReno.cpp
  QuicCubic.cpp
  ServerCongestionControllerFactory.cpp
  SimulatedTBF.cpp
  StaticCwndCongestionController.cpp
  TokenlessPacer.cpp
)

set_property(TARGET mvfst_cc_algo PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_cc_algo PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
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
  DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

add_subdirectory(test)
