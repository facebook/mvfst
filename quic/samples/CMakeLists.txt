# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

add_library(
  mvfst_echohandler STATIC
  echo/EchoClient.h
  echo/EchoHandler.h
  echo/EchoServer.h
)

target_include_directories(
  mvfst_echohandler PUBLIC
  $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
  ${QUIC_EXTRA_INCLUDE_DIRECTORIES}
  $<INSTALL_INTERFACE:include/>
)

target_compile_options(
  mvfst_echohandler
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

target_link_libraries(
  mvfst_echohandler PUBLIC
  Folly::folly
  fizz::fizz
  mvfst_logging
  mvfst_transport
  mvfst_client
  mvfst_test_utils
  mvfst_server
  ${LIBGTEST_LIBRARY}
)

install(
  TARGETS mvfst_echohandler
  DESTINATION lib
)

file(
  GLOB_RECURSE QUIC_API_HEADERS_TOINSTALL
  RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
  *.h
)
list(FILTER QUIC_API_HEADERS_TOINSTALL EXCLUDE REGEX test/)
foreach(header ${QUIC_API_HEADERS_TOINSTALL})
  get_filename_component(header_dir ${header} DIRECTORY)
  install(FILES ${header} DESTINATION include/quic/samples/${header_dir})
endforeach()

add_executable(echo echo/main.cpp)
target_link_libraries(
  echo PUBLIC
  mvfst_echohandler
  mvfst_test_utils
  ${GFLAGS_LIBRARIES}
  ${LIBGMOCK_LIBRARIES}
  ${LIBGTEST_LIBRARY}
)
