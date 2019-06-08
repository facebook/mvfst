# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

include(ExternalProject)
list(APPEND PREFIX_PATH ${CMAKE_PREFIX_PATH} ${CMAKE_INSTALL_PREFIX})
# Construct platform aware cmake args since on OSX
# it requires path to the openssl libs
list(APPEND CMAKE_ARGS
      -DCMAKE_BUILD_TYPE:STRING=RelWithDebInfo
      -DCMAKE_PREFIX_PATH:STRING=${PREFIX_PATH}
      -DBUILD_TESTS:STRING=OFF
)
if(UNIX AND APPLE)
  list(APPEND CMAKE_ARGS
      -DOPENSSL_ROOT_DIR:STRING=${OPENSSL_ROOT_DIR}
      -DOPENSSL_LIBRARIES:STRING=${OPENSSL_LIBRARIES}
)
else()
  find_package(OpenSSL REQUIRED)
endif()
find_package(Sodium REQUIRED)

# Consume Fizz as an external project
ExternalProject_Add(
  fizz_project
  GIT_REPOSITORY https://github.com/facebookincubator/fizz
  PREFIX fizz_project
  SOURCE_SUBDIR fizz
  # Disable install step
  INSTALL_COMMAND ""
  CMAKE_CACHE_ARGS ${CMAKE_ARGS}
)
set(FIZZ_TARGET fizz_project)
ExternalProject_Get_Property(fizz_project source_dir)
set(FIZZ_SOURCE_DIR ${source_dir})
set(FIZZ_PROJECT ${source_dir})
ExternalProject_Get_Property(fizz_project binary_dir)
set(FIZZ_BINARY_DIR ${binary_dir})

# Setup fizz libraries and include dirs
set(LIBFIZZ_LIBRARY_LOCATION
  "${FIZZ_BINARY_DIR}/${CMAKE_CFG_INTDIR}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}fizz${CMAKE_STATIC_LIBRARY_SUFFIX}"
)
add_library(mvfst_fizz STATIC IMPORTED)
set_target_properties(mvfst_fizz PROPERTIES IMPORTED_LOCATION "${LIBFIZZ_LIBRARY_LOCATION}")
set_target_properties(mvfst_fizz PROPERTIES INTERFACE_LINK_LIBRARIES Folly::folly ${OPENSSL_LIBRARIES} ${sodium_LIBRARIES})

set(LIBFIZZ_LIBRARY mvfst_fizz)
set(LIBFIZZ_INCLUDE_DIR "${source_dir}")
