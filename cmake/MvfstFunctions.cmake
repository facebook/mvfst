# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
#
# Functions for building granular mvfst libraries.

# Initialize global properties for tracking targets and deferred dependencies
set_property(GLOBAL PROPERTY MVFST_COMPONENT_TARGETS)
set_property(GLOBAL PROPERTY MVFST_DEFERRED_DEPS)
set_property(GLOBAL PROPERTY MVFST_GRANULAR_INTERFACE_TARGETS)

# Define a granular mvfst library that:
# 1. Compiles sources ONCE via OBJECT library
# 2. Creates a STATIC library for individual linking (static builds)
# 3. Creates an INTERFACE library linking to monolithic mvfst (shared builds)
# 4. Defers internal mvfst deps to be resolved later
# 5. Tracks OBJECT target for monolithic aggregation
# 6. Creates mvfst:: namespace alias
#
# Usage:
#   mvfst_add_library(mvfst_codec_types
#     SRCS Types.cpp
#     DEPS mvfst_constants             # Private dependencies
#     EXPORTED_DEPS Folly::folly_io_iobuf  # Public dependencies (propagated)
#   )
function(mvfst_add_library _target_name)
  cmake_parse_arguments(
    MVFST_LIB
    ""                              # Options (boolean flags)
    ""                              # Single-value args
    "SRCS;DEPS;EXPORTED_DEPS"       # Multi-value args
    ${ARGN}
  )

  set(_sources ${MVFST_LIB_SRCS})
  if(NOT _sources)
    # Legacy support: if no SRCS keyword, treat remaining args as sources
    set(_sources ${MVFST_LIB_UNPARSED_ARGUMENTS})
  endif()

  # Object library name - used for monolithic aggregation
  set(_obj_target "${_target_name}_obj")

  # Skip if no sources (header-only library)
  list(LENGTH _sources _src_count)
  if(_src_count EQUAL 0)
    # Header-only: create INTERFACE library
    add_library(${_target_name} INTERFACE)
    target_include_directories(${_target_name}
      INTERFACE
        $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
        $<INSTALL_INTERFACE:include/>
    )

    # Link exported deps for INTERFACE libraries
    if(MVFST_LIB_EXPORTED_DEPS)
      target_link_libraries(${_target_name} INTERFACE ${MVFST_LIB_EXPORTED_DEPS})
    endif()

    install(TARGETS ${_target_name} EXPORT mvfst-exports)
    add_library(mvfst::${_target_name} ALIAS ${_target_name})
    return()
  endif()

  # 1. Create OBJECT library (compiles sources once)
  add_library(${_obj_target} OBJECT ${_sources})

  set_property(TARGET ${_obj_target} PROPERTY VERSION ${PACKAGE_VERSION})

  if(BUILD_SHARED_LIBS)
    set_property(TARGET ${_obj_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
  endif()

  target_include_directories(${_obj_target}
    PUBLIC
      $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
      $<INSTALL_INTERFACE:include/>
  )

  target_compile_options(${_obj_target}
    PRIVATE
    ${_QUIC_COMMON_COMPILE_OPTIONS}
  )

  target_compile_features(${_obj_target} PUBLIC cxx_std_20)

  # Separate mvfst internal deps (defer) from external deps (link immediately)
  set(_immediate_deps "")
  set(_mvfst_deps "")
  foreach(_dep IN LISTS MVFST_LIB_EXPORTED_DEPS)
    if(_dep MATCHES "^mvfst_")
      list(APPEND _mvfst_deps ${_dep})
    else()
      # Folly::*, fizz::*, external libs, etc. - link immediately
      list(APPEND _immediate_deps ${_dep})
    endif()
  endforeach()

  # Link non-mvfst deps immediately - they provide include paths needed at compile time
  if(_immediate_deps)
    target_link_libraries(${_obj_target} PUBLIC ${_immediate_deps})
  endif()

  # For shared builds: link Folly::folly and fizz::fizz to OBJECT libraries to get transitive
  # includes. We can't link mvfst internal deps because they're INTERFACE libraries
  # linking to monolithic mvfst, creating cycles.
  if(BUILD_SHARED_LIBS)
    target_link_libraries(${_obj_target} PUBLIC Folly::folly fizz::fizz)
  endif()

  # Defer internal mvfst dependencies until all targets are created
  # Only for static builds - in shared builds, mvfst internal deps are INTERFACE
  # libraries linking to monolithic mvfst, which would create cycles
  if(NOT BUILD_SHARED_LIBS)
    if(_mvfst_deps)
      list(JOIN _mvfst_deps "," _deps_str)
      set_property(GLOBAL APPEND PROPERTY MVFST_DEFERRED_DEPS
        "${_obj_target}|PUBLIC|${_deps_str}"
      )
    endif()
    if(MVFST_LIB_DEPS)
      list(JOIN MVFST_LIB_DEPS "," _deps_str)
      set_property(GLOBAL APPEND PROPERTY MVFST_DEFERRED_DEPS
        "${_obj_target}|PRIVATE|${_deps_str}"
      )
    endif()
  endif()

  # Track OBJECT target for monolithic aggregation
  set_property(GLOBAL APPEND PROPERTY MVFST_COMPONENT_TARGETS ${_obj_target})

  # 2. Create the granular library target
  if(BUILD_SHARED_LIBS)
    # For shared builds: create INTERFACE library that will link to monolithic mvfst
    add_library(${_target_name} INTERFACE)

    target_include_directories(${_target_name}
      INTERFACE
        $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
        $<INSTALL_INTERFACE:include/>
    )

    # Track this target to link to mvfst after monolithic library is created
    set_property(GLOBAL APPEND PROPERTY MVFST_GRANULAR_INTERFACE_TARGETS ${_target_name})

    install(TARGETS ${_target_name} EXPORT mvfst-exports)
  else()
    # For static builds: create STATIC library
    add_library(${_target_name} STATIC $<TARGET_OBJECTS:${_obj_target}>)

    set_property(TARGET ${_target_name} PROPERTY VERSION ${PACKAGE_VERSION})

    target_include_directories(${_target_name}
      PUBLIC
        $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
        $<INSTALL_INTERFACE:include/>
    )

    target_compile_features(${_target_name} PUBLIC cxx_std_20)

    # Link non-mvfst deps immediately (reuse _immediate_deps computed above)
    if(_immediate_deps)
      target_link_libraries(${_target_name} PUBLIC ${_immediate_deps})
    endif()

    # Defer internal mvfst dependencies for STATIC library too (reuse _mvfst_deps)
    if(_mvfst_deps)
      list(JOIN _mvfst_deps "," _deps_str)
      set_property(GLOBAL APPEND PROPERTY MVFST_DEFERRED_DEPS
        "${_target_name}|PUBLIC|${_deps_str}"
      )
    endif()
    if(MVFST_LIB_DEPS)
      list(JOIN MVFST_LIB_DEPS "," _deps_str)
      set_property(GLOBAL APPEND PROPERTY MVFST_DEFERRED_DEPS
        "${_target_name}|PRIVATE|${_deps_str}"
      )
    endif()

    install(
      TARGETS ${_target_name}
      EXPORT mvfst-exports
      LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
  endif()

  # Create alias for the library
  add_library(mvfst::${_target_name} ALIAS ${_target_name})
endfunction()

# Create a backwards-compatible alias target
# This creates an INTERFACE library with the old name that links to the new target
function(mvfst_add_compat_alias _old_name _new_name)
  if(NOT TARGET ${_new_name})
    message(WARNING "Cannot create compat alias ${_old_name}: target ${_new_name} does not exist")
    return()
  endif()

  add_library(${_old_name} INTERFACE)
  target_link_libraries(${_old_name} INTERFACE ${_new_name})
  install(TARGETS ${_old_name} EXPORT mvfst-exports)
  add_library(mvfst::${_old_name} ALIAS ${_old_name})
endfunction()

# Create the monolithic mvfst library from all component OBJECT libraries
# Call this after all add_subdirectory() calls, before mvfst_resolve_deferred_dependencies()
function(mvfst_create_monolithic_library)
  get_property(_component_targets GLOBAL PROPERTY MVFST_COMPONENT_TARGETS)

  if(NOT _component_targets)
    message(STATUS "No component targets found, skipping monolithic library creation")
    return()
  endif()

  # Collect all object files from component targets
  set(_all_objects)
  foreach(_target IN LISTS _component_targets)
    list(APPEND _all_objects $<TARGET_OBJECTS:${_target}>)
  endforeach()

  # Create the monolithic library
  add_library(mvfst ${_all_objects})

  if(BUILD_SHARED_LIBS)
    set_property(TARGET mvfst PROPERTY POSITION_INDEPENDENT_CODE ON)
    set_property(TARGET mvfst PROPERTY VERSION ${PACKAGE_VERSION})
  endif()

  target_include_directories(mvfst
    PUBLIC
      $<BUILD_INTERFACE:${QUIC_FBCODE_ROOT}>
      $<INSTALL_INTERFACE:include/>
  )

  target_compile_features(mvfst PUBLIC cxx_std_20)

  # Link all dependencies
  target_link_libraries(mvfst
    PUBLIC
      Folly::folly
      fizz::fizz
      ${OPENSSL_LIBRARIES}
      Threads::Threads
    PRIVATE
      ${GLOG_LIBRARIES}
      ${GFLAG_DEPENDENCIES}
      ${CMAKE_DL_LIBS}
  )

  # Create alias for consistency
  add_library(mvfst::mvfst ALIAS mvfst)

  # For shared builds: link all granular INTERFACE targets to the monolithic library
  if(BUILD_SHARED_LIBS)
    cmake_policy(SET CMP0079 NEW)
    get_property(_interface_targets GLOBAL PROPERTY MVFST_GRANULAR_INTERFACE_TARGETS)
    foreach(_target IN LISTS _interface_targets)
      target_link_libraries(${_target} INTERFACE mvfst)
    endforeach()
  endif()
endfunction()

# Resolve all deferred dependencies after all targets have been created
# Call this after all add_subdirectory() calls and mvfst_create_monolithic_library()
function(mvfst_resolve_deferred_dependencies)
  # Allow linking targets defined in other directories
  cmake_policy(SET CMP0079 NEW)

  get_property(_deferred_deps GLOBAL PROPERTY MVFST_DEFERRED_DEPS)

  foreach(_spec IN LISTS _deferred_deps)
    # Parse the spec: "target|visibility|dep1,dep2,..."
    string(REPLACE "|" ";" _parts "${_spec}")
    list(LENGTH _parts _len)
    if(_len LESS 3)
      continue()
    endif()

    list(GET _parts 0 _target)
    list(GET _parts 1 _visibility)
    list(GET _parts 2 _deps_str)

    # Split deps by comma
    string(REPLACE "," ";" _deps "${_deps_str}")

    # Filter to only existing targets (skip deps that weren't generated)
    set(_valid_deps "")
    foreach(_dep IN LISTS _deps)
      if(TARGET ${_dep})
        list(APPEND _valid_deps ${_dep})
      endif()
    endforeach()

    if(_valid_deps)
      target_link_libraries(${_target} ${_visibility} ${_valid_deps})
    endif()
  endforeach()
endfunction()

# =============================================================================
# Header installation function
# =============================================================================
# Install headers preserving directory structure relative to rootDir
# Usage: mvfst_install_headers(quic ${CMAKE_CURRENT_SOURCE_DIR} ${HEADERS})
function(mvfst_install_headers rootName rootDir)
  file(TO_CMAKE_PATH "${rootDir}" rootDir)
  string(LENGTH "${rootDir}" rootDirLength)
  foreach(fil ${ARGN})
    file(TO_CMAKE_PATH "${fil}" filePath)
    string(FIND "${filePath}" "/" rIdx REVERSE)
    if(rIdx EQUAL -1)
      continue()
    endif()
    string(SUBSTRING "${filePath}" 0 ${rIdx} filePath)

    string(LENGTH "${filePath}" filePathLength)
    string(FIND "${filePath}" "${rootDir}" rIdx)
    if(rIdx EQUAL 0)
      math(EXPR filePathLength "${filePathLength} - ${rootDirLength}")
      string(SUBSTRING "${filePath}" ${rootDirLength} ${filePathLength} fileGroup)
      install(FILES ${fil}
              DESTINATION ${INCLUDE_INSTALL_DIR}/${rootName}${fileGroup})
    endif()
  endforeach()
endfunction()
