"""Native library merge map for quic.

Generated by xplat/cross_plat_devx/somerge_maps/compute_merge_maps.py

@generated SignedSource<<7d0609d259d02ba66cc37ba7fdb6229a>>
"""

# Entry Points:
#    //xplat/quic/api:transport
#    //xplat/quic/client:client
#    //xplat/quic/codec:types
#    //xplat/quic/common/events:eventbase
#    //xplat/quic/common/events:folly_eventbase
#    //xplat/quic/common/events:highres_quic_timer
#    //xplat/quic/common/events:quic_timer
#    //xplat/quic/common/udpsocket:folly_async_udp_socket
#    //xplat/quic/common/udpsocket:quic_async_udp_socket
#    //xplat/quic/common:buf_util
#    //xplat/quic/congestion_control:congestion_controller_factory
#    //xplat/quic/fizz/client/handshake:fizz_client_handshake
#    //xplat/quic/fizz/client/handshake:token_cache
#    //xplat/quic/logging:qlogger
#    //xplat/quic/state:quic_priority_queue
#    //xplat/quic/state:quic_state_machine
#    //xplat/quic:constants
#    //xplat/quic:exception
QUIC_NATIVE_LIBRARY_MERGE_MAP = [
    "fbsource//xplat/quic/api:ack_schedulerAndroid",
    "fbsource//xplat/quic/api:ack_schedulerAndroidAndroid",
    "fbsource//xplat/quic/api:loop_detector_callbackAndroid",
    "fbsource//xplat/quic/api:loop_detector_callbackAndroidAndroid",
    "fbsource//xplat/quic/api:quic_batch_writerAndroid",
    "fbsource//xplat/quic/api:quic_batch_writerAndroidAndroid",
    "fbsource//xplat/quic/api:quic_callbacksAndroid",
    "fbsource//xplat/quic/api:quic_callbacksAndroidAndroid",
    "fbsource//xplat/quic/api:transportAndroid",
    "fbsource//xplat/quic/api:transportAndroidAndroid",
    "fbsource//xplat/quic/api:transport_helpersAndroid",
    "fbsource//xplat/quic/api:transport_helpersAndroidAndroid",
    "fbsource//xplat/quic/api:transport_liteAndroid",
    "fbsource//xplat/quic/api:transport_liteAndroidAndroid",
    "fbsource//xplat/quic/client:cached_server_tpAndroid",
    "fbsource//xplat/quic/client:cached_server_tpAndroidAndroid",
    "fbsource//xplat/quic/client:clientAndroid",
    "fbsource//xplat/quic/client:client_extensionAndroid",
    "fbsource//xplat/quic/client:client_extensionAndroidAndroid",
    "fbsource//xplat/quic/client:client_liteAndroid",
    "fbsource//xplat/quic/client:client_liteAndroidAndroid",
    "fbsource//xplat/quic/client:state_and_handshakeAndroid",
    "fbsource//xplat/quic/client:state_and_handshakeAndroidAndroid",
    "fbsource//xplat/quic/codec:codecAndroid",
    "fbsource//xplat/quic/codec:codecAndroidAndroid",
    "fbsource//xplat/quic/codec:decodeAndroid",
    "fbsource//xplat/quic/codec:decodeAndroidAndroid",
    "fbsource//xplat/quic/codec:packet_numberAndroid",
    "fbsource//xplat/quic/codec:packet_numberAndroidAndroid",
    "fbsource//xplat/quic/codec:packet_number_cipherAndroid",
    "fbsource//xplat/quic/codec:packet_number_cipherAndroidAndroid",
    "fbsource//xplat/quic/codec:pktbuilderAndroid",
    "fbsource//xplat/quic/codec:pktbuilderAndroidAndroid",
    "fbsource//xplat/quic/codec:pktrebuilderAndroid",
    "fbsource//xplat/quic/codec:pktrebuilderAndroidAndroid",
    "fbsource//xplat/quic/codec:typesAndroid",
    "fbsource//xplat/quic/codec:typesAndroidAndroid",
    "fbsource//xplat/quic/common/events:eventbaseAndroid",
    "fbsource//xplat/quic/common/events:eventbaseAndroidAndroid",
    "fbsource//xplat/quic/common/events:folly_eventbaseAndroid",
    "fbsource//xplat/quic/common/events:folly_eventbaseAndroidAndroid",
    "fbsource//xplat/quic/common/events:highres_quic_timerAndroid",
    "fbsource//xplat/quic/common/events:quic_timerAndroid",
    "fbsource//xplat/quic/common/events:quic_timerAndroidAndroid",
    "fbsource//xplat/quic/common/third-party:better_enumsAndroid",
    "fbsource//xplat/quic/common/third-party:better_enumsAndroidAndroid",
    "fbsource//xplat/quic/common/third-party:tiny_optionalAndroid",
    "fbsource//xplat/quic/common/third-party:tiny_optionalAndroidAndroid",
    "fbsource//xplat/quic/common/udpsocket:folly_async_udp_socketAndroid",
    "fbsource//xplat/quic/common/udpsocket:quic_async_udp_socketAndroid",
    "fbsource//xplat/quic/common/udpsocket:quic_async_udp_socketAndroidAndroid",
    "fbsource//xplat/quic/common/udpsocket:quic_async_udp_socket_implAndroid",
    "fbsource//xplat/quic/common/udpsocket:quic_async_udp_socket_implAndroidAndroid",
    "fbsource//xplat/quic/common:buf_accessorAndroid",
    "fbsource//xplat/quic/common:buf_accessorAndroidAndroid",
    "fbsource//xplat/quic/common:buf_utilAndroid",
    "fbsource//xplat/quic/common:buf_utilAndroidAndroid",
    "fbsource//xplat/quic/common:circular_dequeAndroid",
    "fbsource//xplat/quic/common:circular_dequeAndroidAndroid",
    "fbsource//xplat/quic/common:enum_arrayAndroid",
    "fbsource//xplat/quic/common:enum_arrayAndroidAndroid",
    "fbsource//xplat/quic/common:interval_setAndroid",
    "fbsource//xplat/quic/common:interval_setAndroidAndroid",
    "fbsource//xplat/quic/common:looperAndroid",
    "fbsource//xplat/quic/common:looperAndroidAndroid",
    "fbsource//xplat/quic/common:network_dataAndroid",
    "fbsource//xplat/quic/common:network_dataAndroidAndroid",
    "fbsource//xplat/quic/common:optionalAndroid",
    "fbsource//xplat/quic/common:optionalAndroidAndroid",
    "fbsource//xplat/quic/common:small_collectionsAndroid",
    "fbsource//xplat/quic/common:small_collectionsAndroidAndroid",
    "fbsource//xplat/quic/common:socket_utilAndroid",
    "fbsource//xplat/quic/common:socket_utilAndroidAndroid",
    "fbsource//xplat/quic/common:time_pointsAndroid",
    "fbsource//xplat/quic/common:time_pointsAndroidAndroid",
    "fbsource//xplat/quic/common:time_utilAndroid",
    "fbsource//xplat/quic/common:time_utilAndroidAndroid",
    "fbsource//xplat/quic/common:variantAndroid",
    "fbsource//xplat/quic/common:variantAndroidAndroid",
    "fbsource//xplat/quic/congestion_control/third_party:chromium_windowed_filterAndroid",
    "fbsource//xplat/quic/congestion_control/third_party:chromium_windowed_filterAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:bandwidthAndroid",
    "fbsource//xplat/quic/congestion_control:bandwidthAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:bbrAndroid",
    "fbsource//xplat/quic/congestion_control:bbr2Android",
    "fbsource//xplat/quic/congestion_control:bbr2AndroidAndroid",
    "fbsource//xplat/quic/congestion_control:bbrAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:bbr_bandwidth_samplerAndroid",
    "fbsource//xplat/quic/congestion_control:bbr_bandwidth_samplerAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:bbr_rtt_samplerAndroid",
    "fbsource//xplat/quic/congestion_control:bbr_rtt_samplerAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:congestion_control_functionsAndroid",
    "fbsource//xplat/quic/congestion_control:congestion_control_functionsAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:congestion_controllerAndroid",
    "fbsource//xplat/quic/congestion_control:congestion_controllerAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:congestion_controller_factoryAndroid",
    "fbsource//xplat/quic/congestion_control:congestion_controller_factoryAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:copaAndroid",
    "fbsource//xplat/quic/congestion_control:copa2Android",
    "fbsource//xplat/quic/congestion_control:copa2AndroidAndroid",
    "fbsource//xplat/quic/congestion_control:copaAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:cubicAndroid",
    "fbsource//xplat/quic/congestion_control:cubicAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:ecn_l4s_trackerAndroid",
    "fbsource//xplat/quic/congestion_control:ecn_l4s_trackerAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:newrenoAndroid",
    "fbsource//xplat/quic/congestion_control:newrenoAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:pacerAndroid",
    "fbsource//xplat/quic/congestion_control:pacerAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:packet_processorAndroid",
    "fbsource//xplat/quic/congestion_control:packet_processorAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:static_cwnd_congestion_controllerAndroid",
    "fbsource//xplat/quic/congestion_control:static_cwnd_congestion_controllerAndroidAndroid",
    "fbsource//xplat/quic/congestion_control:throttling_signal_providerAndroid",
    "fbsource//xplat/quic/congestion_control:throttling_signal_providerAndroidAndroid",
    "fbsource//xplat/quic/dsr:dsr_packetization_request_senderAndroid",
    "fbsource//xplat/quic/dsr:dsr_packetization_request_senderAndroidAndroid",
    "fbsource//xplat/quic/fizz/client/handshake:fizz_client_handshakeAndroid",
    "fbsource//xplat/quic/fizz/client/handshake:psk_cacheAndroid",
    "fbsource//xplat/quic/fizz/client/handshake:psk_cacheAndroidAndroid",
    "fbsource//xplat/quic/fizz/client/handshake:token_cacheAndroid",
    "fbsource//xplat/quic/fizz/handshake:fizz_handshakeAndroid",
    "fbsource//xplat/quic/fizz/handshake:fizz_handshakeAndroidAndroid",
    "fbsource//xplat/quic/flowcontrol:flow_controlAndroid",
    "fbsource//xplat/quic/flowcontrol:flow_controlAndroidAndroid",
    "fbsource//xplat/quic/handshake:aeadAndroid",
    "fbsource//xplat/quic/handshake:aeadAndroidAndroid",
    "fbsource//xplat/quic/handshake:handshakeAndroid",
    "fbsource//xplat/quic/handshake:handshakeAndroidAndroid",
    "fbsource//xplat/quic/handshake:retry_integrity_tag_generatorAndroid",
    "fbsource//xplat/quic/handshake:retry_integrity_tag_generatorAndroidAndroid",
    "fbsource//xplat/quic/handshake:transport_parametersAndroid",
    "fbsource//xplat/quic/handshake:transport_parametersAndroidAndroid",
    "fbsource//xplat/quic/happyeyeballs:happyeyeballsAndroid",
    "fbsource//xplat/quic/happyeyeballs:happyeyeballsAndroidAndroid",
    "fbsource//xplat/quic/logging:qloggerAndroid",
    "fbsource//xplat/quic/logging:qloggerAndroidAndroid",
    "fbsource//xplat/quic/logging:qlogger_constantsAndroid",
    "fbsource//xplat/quic/logging:qlogger_constantsAndroidAndroid",
    "fbsource//xplat/quic/loss:lossAndroid",
    "fbsource//xplat/quic/loss:lossAndroidAndroid",
    "fbsource//xplat/quic/observer:socket_observer_containerAndroid",
    "fbsource//xplat/quic/observer:socket_observer_containerAndroidAndroid",
    "fbsource//xplat/quic/observer:socket_observer_interfaceAndroid",
    "fbsource//xplat/quic/observer:socket_observer_interfaceAndroidAndroid",
    "fbsource//xplat/quic/observer:socket_observer_typesAndroid",
    "fbsource//xplat/quic/observer:socket_observer_typesAndroidAndroid",
    "fbsource//xplat/quic/state/stream:streamAndroid",
    "fbsource//xplat/quic/state/stream:streamAndroidAndroid",
    "fbsource//xplat/quic/state:ack_eventAndroid",
    "fbsource//xplat/quic/state:ack_eventAndroidAndroid",
    "fbsource//xplat/quic/state:ack_frequency_functionsAndroid",
    "fbsource//xplat/quic/state:ack_frequency_functionsAndroidAndroid",
    "fbsource//xplat/quic/state:ack_handlerAndroid",
    "fbsource//xplat/quic/state:ack_handlerAndroidAndroid",
    "fbsource//xplat/quic/state:ack_statesAndroid",
    "fbsource//xplat/quic/state:ack_statesAndroidAndroid",
    "fbsource//xplat/quic/state:cloned_packet_identifierAndroid",
    "fbsource//xplat/quic/state:cloned_packet_identifierAndroidAndroid",
    "fbsource//xplat/quic/state:datagram_handlerAndroid",
    "fbsource//xplat/quic/state:datagram_handlerAndroidAndroid",
    "fbsource//xplat/quic/state:loss_stateAndroid",
    "fbsource//xplat/quic/state:loss_stateAndroidAndroid",
    "fbsource//xplat/quic/state:outstanding_packetAndroid",
    "fbsource//xplat/quic/state:outstanding_packetAndroidAndroid",
    "fbsource//xplat/quic/state:pacing_functionsAndroid",
    "fbsource//xplat/quic/state:pacing_functionsAndroidAndroid",
    "fbsource//xplat/quic/state:quic_connection_statsAndroid",
    "fbsource//xplat/quic/state:quic_connection_statsAndroidAndroid",
    "fbsource//xplat/quic/state:quic_priority_queueAndroid",
    "fbsource//xplat/quic/state:quic_priority_queueAndroidAndroid",
    "fbsource//xplat/quic/state:quic_state_machineAndroid",
    "fbsource//xplat/quic/state:quic_state_machineAndroidAndroid",
    "fbsource//xplat/quic/state:quic_stream_utilitiesAndroid",
    "fbsource//xplat/quic/state:quic_stream_utilitiesAndroidAndroid",
    "fbsource//xplat/quic/state:retransmission_policyAndroid",
    "fbsource//xplat/quic/state:retransmission_policyAndroidAndroid",
    "fbsource//xplat/quic/state:simple_frame_functionsAndroid",
    "fbsource//xplat/quic/state:simple_frame_functionsAndroidAndroid",
    "fbsource//xplat/quic/state:state_functionsAndroid",
    "fbsource//xplat/quic/state:state_functionsAndroidAndroid",
    "fbsource//xplat/quic/state:stats_callbackAndroid",
    "fbsource//xplat/quic/state:stats_callbackAndroidAndroid",
    "fbsource//xplat/quic/state:stream_functionsAndroid",
    "fbsource//xplat/quic/state:stream_functionsAndroidAndroid",
    "fbsource//xplat/quic/state:transport_settingsAndroid",
    "fbsource//xplat/quic/state:transport_settingsAndroidAndroid",
    "fbsource//xplat/quic:constantsAndroid",
    "fbsource//xplat/quic:constantsAndroidAndroid",
    "fbsource//xplat/quic:exceptionAndroid",
    "fbsource//xplat/quic:exceptionAndroidAndroid",
]
