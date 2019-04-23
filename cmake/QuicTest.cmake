# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

include(CTest)
if(BUILD_TESTS)
  include(GoogleTest)
  find_package(GMock MODULE REQUIRED)
endif()

function(quic_add_test)
  if(NOT BUILD_TESTS)
    return()
  endif()

  set(options)
  set(one_value_args TARGET WORKING_DIRECTORY PREFIX)
  set(multi_value_args SOURCES DEPENDS INCLUDES EXTRA_ARGS)
  cmake_parse_arguments(PARSE_ARGV 0 QUIC_TEST "${options}" "${one_value_args}" "${multi_value_args}")

  if(NOT QUIC_TEST_TARGET)
    message(FATAL_ERROR "The TARGET parameter is mandatory.")
  endif()

  if(NOT QUIC_TEST_SOURCES)
    set(QUIC_TEST_SOURCES "${QUIC_TEST_TARGET}.cpp")
  endif()

  add_executable(${QUIC_TEST_TARGET}
    "${QUIC_TEST_SOURCES}"
    # implementation of 'main()' that calls folly::init
    "${QUIC_FBCODE_ROOT}/quic/common/test/TestMain.cpp"
  )
  target_compile_options(
    ${QUIC_TEST_TARGET} PRIVATE
    ${_QUIC_COMMON_COMPILE_OPTIONS}
  )
  target_link_libraries(${QUIC_TEST_TARGET} PRIVATE
    "${QUIC_TEST_DEPENDS}"
  )
  target_include_directories(${QUIC_TEST_TARGET} PRIVATE
    "${QUIC_TEST_INCLUDES}"
  )

  gtest_add_tests(TARGET ${QUIC_TEST_TARGET}
    EXTRA_ARGS "${QUIC_TEST_EXTRA_ARGS}"
    WORKING_DIRECTORY ${QUIC_TEST_WORKING_DIRECTORY}
    TEST_PREFIX ${QUIC_TEST_PREFIX}
  TEST_LIST QUIC_TEST_CASES)

  target_link_libraries(${QUIC_TEST_TARGET} PRIVATE
    ${LIBGMOCK_LIBRARIES}
  )
  target_include_directories(${QUIC_TEST_TARGET} PRIVATE
    ${LIBGMOCK_INCLUDE_DIR}
    ${QUIC_EXTRA_INCLUDE_DIRECTORIES}
  )
  target_compile_definitions(${QUIC_TEST_TARGET} PRIVATE ${LIBGMOCK_DEFINES})
  set_tests_properties(${QUIC_TEST_CASES} PROPERTIES TIMEOUT 120)
endfunction()
