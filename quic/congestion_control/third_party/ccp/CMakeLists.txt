# The core CCP library is written in rust, thus we need to use cargo to build it.
# This file externally calls out to cargo and then sets some variables to tell cmake where to find the generated library.

if(DEFINED CCP_ENABLED)

  # choose cargo build mode based on cmake build mode
  if (CMAKE_BUILD_TYPE STREQUAL "Debug")
  	# always need to build with nightly because portus (ccp rust library) requires it (at the moment)
  	set(CARGO_CMD cargo +nightly build --lib)
  	set(TARGET_DIR "debug")
  else ()
  	# always need to build with nightly because portus (ccp rust library) requires it (at the moment)
  	set(CARGO_CMD cargo +nightly build --lib --release)
  	set(TARGET_DIR "release")
  endif ()
  
  # cargo will place the library here
  set(CARGO_TARGET_LOC "${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}/libstartccp.a")
  # but cmake likes the library to be here (i.e. no ${TARGET_DIR})
  set(CMAKE_TARGET_LOC "${CMAKE_CURRENT_BINARY_DIR}/libstartccp.a")
  
  # since cmake isn't building ccp directly (cargo is), it doesn't know which source files it depends on 
  # (and thus when to rebuild it, so we need to specify it manually below with "DEPENDS"...)
  # the set of source files is any rust or Cargo.toml file in quic/congestion_control/third_party 
  file(GLOB_RECURSE ALG_SRC ${CMAKE_CURRENT_SOURCE_DIR}/../ *.rs Cargo.toml)
  message(STATUS "found alg files: ${ALG_SRC}")
  
  # run cargo to actually build the library, 
  # then copy the library to where cmake wants it to be 
  add_custom_command(
  	OUTPUT ${CMAKE_TARGET_LOC}
  	COMMAND CARGO_TARGET_DIR=${CMAKE_CURRENT_BINARY_DIR} ${CARGO_CMD}
  	COMMAND cp ${CARGO_TARGET_LOC} ${CMAKE_TARGET_LOC}
  	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
  	DEPENDS ${ALG_SRC}
  	COMMENT "Building CCP algorithms..."
  	VERBATIM
  )
  # we make a target that depends on the output of cargo (as opposed to generating it here directly) so that cmake 
  # doesn't re-run cargo every time 
  add_custom_target(libstartccp DEPENDS ${CMAKE_TARGET_LOC})
  
  # each cmakelists.txt has its own scope, so we can't access CMAKE_TARGET_LOC in the scope where we need to use it as a dependency
  # so instead, we set it as a property of this target, which we can lookup later using get_target_properties()
  set_target_properties(libstartccp PROPERTIES LOCATION ${CMAKE_TARGET_LOC})

endif()
