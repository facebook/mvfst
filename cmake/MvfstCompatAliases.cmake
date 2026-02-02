# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
#
# Manually maintained - backwards compatibility aliases for downstream projects
# (proxygen, moxygen, thrift, etc.)
#
# These aliases map old target names to the new granular targets, including
# all transitive dependencies that the old targets had.

# Helper macro to create a compat alias with multiple dependencies
macro(mvfst_compat_alias _name)
  add_library(${_name} INTERFACE)
  target_link_libraries(${_name} INTERFACE ${ARGN})
  install(TARGETS ${_name} EXPORT mvfst-exports)
  add_library(mvfst::${_name} ALIAS ${_name})
endmacro()

# =============================================================================
# Backwards compatibility aliases
# =============================================================================

# mvfst_transport: old target included QuicStreamAsyncTransport.cpp
mvfst_compat_alias(mvfst_transport
  mvfst_api_transport
  mvfst_api_stream_async_transport
)

# mvfst_client: old target linked to mvfst_qlogger
mvfst_compat_alias(mvfst_client
  mvfst_client_client
  mvfst_logging_file_qlogger
)

# mvfst_server: old target included fizz server sources and linked to mvfst_qlogger
mvfst_compat_alias(mvfst_server
  mvfst_server_server
  mvfst_fizz_server_handshake
  mvfst_logging_file_qlogger
)

# mvfst_events: simple rename
mvfst_compat_alias(mvfst_events
  mvfst_common_events_eventbase
)

# mvfst_fizz_client: simple rename
mvfst_compat_alias(mvfst_fizz_client
  mvfst_fizz_client_handshake
)

# mvfst_observer: simple rename
mvfst_compat_alias(mvfst_observer
  mvfst_observer_socket_observer_container
)

# mvfst_state_machine: simple rename
mvfst_compat_alias(mvfst_state_machine
  mvfst_state_quic_state_machine
)

# mvfst_server_async_tran: old target linked to mvfst_server and mvfst_qlogger
mvfst_compat_alias(mvfst_server_async_tran
  mvfst_server_async_tran_server_async_transport
  mvfst_server_server
  mvfst_logging_file_qlogger
)

# mvfst_qlogger: simple rename to file_qlogger
mvfst_compat_alias(mvfst_qlogger
  mvfst_logging_file_qlogger
)
