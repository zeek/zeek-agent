#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.10)

function(cafMain)
  set(CAF_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/src")

  generateCafCore()
  generateCafIO()
  generateCafOpenSSL()

  add_library(thirdparty_caf INTERFACE)
  target_link_libraries(thirdparty_caf INTERFACE
    thirdparty_caf_core
    thirdparty_caf_io
    thirdparty_caf_openssl
  )
endfunction()

function(generateCafCore)
  set(library_root "${CAF_ROOT}/libcaf_core")

  add_library(thirdparty_caf_core
    "${library_root}/src/abstract_actor.cpp"
    "${library_root}/src/abstract_channel.cpp"
    "${library_root}/src/abstract_composable_behavior.cpp"
    "${library_root}/src/abstract_coordinator.cpp"
    "${library_root}/src/abstract_group.cpp"
    "${library_root}/src/actor_addr.cpp"
    "${library_root}/src/actor_clock.cpp"
    "${library_root}/src/actor_companion.cpp"
    "${library_root}/src/actor_config.cpp"
    "${library_root}/src/actor_control_block.cpp"
    "${library_root}/src/actor.cpp"
    "${library_root}/src/actor_ostream.cpp"
    "${library_root}/src/actor_pool.cpp"
    "${library_root}/src/actor_proxy.cpp"
    "${library_root}/src/actor_registry.cpp"
    "${library_root}/src/actor_system_config.cpp"
    "${library_root}/src/actor_system.cpp"
    "${library_root}/src/append_hex.cpp"
    "${library_root}/src/atom.cpp"
    "${library_root}/src/attachable.cpp"
    "${library_root}/src/behavior.cpp"
    "${library_root}/src/behavior_impl.cpp"
    "${library_root}/src/behavior_stack.cpp"
    "${library_root}/src/blocking_actor.cpp"
    "${library_root}/src/blocking_behavior.cpp"
    "${library_root}/src/chars.cpp"
    "${library_root}/src/concatenated_tuple.cpp"
    "${library_root}/src/config_option_adder.cpp"
    "${library_root}/src/config_option.cpp"
    "${library_root}/src/config_option_set.cpp"
    "${library_root}/src/config_value.cpp"
    "${library_root}/src/decorated_tuple.cpp"
    "${library_root}/src/default_attachable.cpp"
    "${library_root}/src/defaults.cpp"
    "${library_root}/src/deserializer.cpp"
    "${library_root}/src/downstream_manager_base.cpp"
    "${library_root}/src/downstream_manager.cpp"
    "${library_root}/src/downstream_messages.cpp"
    "${library_root}/src/duration.cpp"
    "${library_root}/src/dynamic_message_data.cpp"
    "${library_root}/src/error.cpp"
    "${library_root}/src/event_based_actor.cpp"
    "${library_root}/src/execution_unit.cpp"
    "${library_root}/src/exit_reason.cpp"
    "${library_root}/src/forwarding_actor_proxy.cpp"
    "${library_root}/src/get_mac_addresses.cpp"
    "${library_root}/src/get_process_id.cpp"
    "${library_root}/src/get_root_uuid.cpp"
    "${library_root}/src/group.cpp"
    "${library_root}/src/group_manager.cpp"
    "${library_root}/src/group_module.cpp"
    "${library_root}/src/inbound_path.cpp"
    "${library_root}/src/ini_consumer.cpp"
    "${library_root}/src/invoke_result_visitor.cpp"
    "${library_root}/src/ipv4_address.cpp"
    "${library_root}/src/ipv4_subnet.cpp"
    "${library_root}/src/ipv6_address.cpp"
    "${library_root}/src/ipv6_subnet.cpp"
    "${library_root}/src/local_actor.cpp"
    "${library_root}/src/logger.cpp"
    "${library_root}/src/mailbox_element.cpp"
    "${library_root}/src/make_config_option.cpp"
    "${library_root}/src/match_case.cpp"
    "${library_root}/src/memory_managed.cpp"
    "${library_root}/src/merged_tuple.cpp"
    "${library_root}/src/message_builder.cpp"
    "${library_root}/src/message.cpp"
    "${library_root}/src/message_data.cpp"
    "${library_root}/src/message_handler.cpp"
    "${library_root}/src/message_view.cpp"
    "${library_root}/src/monitorable_actor.cpp"
    "${library_root}/src/node_id.cpp"
    "${library_root}/src/outbound_path.cpp"
    "${library_root}/src/pec.cpp"
    "${library_root}/src/pretty_type_name.cpp"
    "${library_root}/src/private_thread.cpp"
    "${library_root}/src/proxy_registry.cpp"
    "${library_root}/src/raise_error.cpp"
    "${library_root}/src/raw_event_based_actor.cpp"
    "${library_root}/src/ref_counted.cpp"
    "${library_root}/src/replies_to.cpp"
    "${library_root}/src/response_promise.cpp"
    "${library_root}/src/resumable.cpp"
    "${library_root}/src/ripemd_160.cpp"
    "${library_root}/src/runtime_settings_map.cpp"
    "${library_root}/src/scheduled_actor.cpp"
    "${library_root}/src/scoped_actor.cpp"
    "${library_root}/src/scoped_execution_unit.cpp"
    "${library_root}/src/sec.cpp"
    "${library_root}/src/sequencer.cpp"
    "${library_root}/src/serializer.cpp"
    "${library_root}/src/set_thread_name.cpp"
    "${library_root}/src/shared_spinlock.cpp"
    "${library_root}/src/simple_actor_clock.cpp"
    "${library_root}/src/skip.cpp"
    "${library_root}/src/splitter.cpp"
    "${library_root}/src/stream_aborter.cpp"
    "${library_root}/src/stream_manager.cpp"
    "${library_root}/src/stream_priority.cpp"
    "${library_root}/src/stringification_inspector.cpp"
    "${library_root}/src/string_view.cpp"
    "${library_root}/src/sync_request_bouncer.cpp"
    "${library_root}/src/term.cpp"
    "${library_root}/src/test_actor_clock.cpp"
    "${library_root}/src/test_coordinator.cpp"
    "${library_root}/src/thread_hook.cpp"
    "${library_root}/src/thread_safe_actor_clock.cpp"
    "${library_root}/src/tick_emitter.cpp"
    "${library_root}/src/timestamp.cpp"
    "${library_root}/src/try_match.cpp"
    "${library_root}/src/type_erased_tuple.cpp"
    "${library_root}/src/type_erased_value.cpp"
    "${library_root}/src/uniform_type_info_map.cpp"
    "${library_root}/src/unprofiled.cpp"
    "${library_root}/src/uri_builder.cpp"
    "${library_root}/src/uri.cpp"
    "${library_root}/src/uri_impl.cpp"
    "${library_root}/src/work_sharing.cpp"
    "${library_root}/src/work_stealing.cpp"
    "${library_root}/src/string_algorithms.cpp"
  )

  target_link_libraries(thirdparty_caf_core PUBLIC
    zeek_common_settings
    zeek_thirdparty_module_settings
  )

  target_compile_features(thirdparty_caf_core INTERFACE cxx_std_11)

  target_include_directories(thirdparty_caf_core SYSTEM PUBLIC
    "${library_root}"
    "${CMAKE_CURRENT_SOURCE_DIR}/generated"
  )
endfunction()

function(generateCafIO)
  set(library_root "${CAF_ROOT}/libcaf_io")

  add_library(thirdparty_caf_io
    "${library_root}/src/abstract_broker.cpp"
    "${library_root}/src/acceptor.cpp"
    "${library_root}/src/acceptor_manager.cpp"
    "${library_root}/src/basp_broker.cpp"
    "${library_root}/src/broker.cpp"
    "${library_root}/src/connection_helper.cpp"
    "${library_root}/src/datagram_handler.cpp"
    "${library_root}/src/datagram_manager.cpp"
    "${library_root}/src/datagram_servant.cpp"
    "${library_root}/src/datagram_servant_impl.cpp"
    "${library_root}/src/default_multiplexer.cpp"
    "${library_root}/src/doorman.cpp"
    "${library_root}/src/doorman_impl.cpp"
    "${library_root}/src/event_handler.cpp"
    "${library_root}/src/header.cpp"
    "${library_root}/src/hook.cpp"
    "${library_root}/src/instance.cpp"
    "${library_root}/src/interfaces.cpp"
    "${library_root}/src/ip_endpoint.cpp"
    "${library_root}/src/manager.cpp"
    "${library_root}/src/message_type.cpp"
    "${library_root}/src/middleman_actor.cpp"
    "${library_root}/src/middleman_actor_impl.cpp"
    "${library_root}/src/middleman.cpp"
    "${library_root}/src/multiplexer.cpp"
    "${library_root}/src/native_socket.cpp"
    "${library_root}/src/pipe_reader.cpp"
    "${library_root}/src/protocol.cpp"
    "${library_root}/src/receive_buffer.cpp"
    "${library_root}/src/routing_table.cpp"
    "${library_root}/src/scribe.cpp"
    "${library_root}/src/scribe_impl.cpp"
    "${library_root}/src/socket_guard.cpp"
    "${library_root}/src/stream.cpp"
    "${library_root}/src/stream_manager.cpp"
    "${library_root}/src/tcp.cpp"
    "${library_root}/src/test_multiplexer.cpp"
    "${library_root}/src/udp.cpp"
  )

  target_link_libraries(thirdparty_caf_io PUBLIC
    zeek_common_settings
    zeek_thirdparty_module_settings
    thirdparty_caf_core
  )
  
  target_compile_features(thirdparty_caf_io INTERFACE cxx_std_11)

  target_include_directories(thirdparty_caf_io SYSTEM PUBLIC
    "${library_root}"
  )
endfunction()

function(generateCafOpenSSL)
  set(library_root "${CAF_ROOT}/libcaf_openssl")

  add_library(thirdparty_caf_openssl
    "${library_root}/src/manager.cpp"
    "${library_root}/src/middleman_actor.cpp"
    "${library_root}/src/publish.cpp"
    "${library_root}/src/remote_actor.cpp"
    "${library_root}/src/session.cpp"
  )

  target_link_libraries(thirdparty_caf_openssl PUBLIC
    zeek_common_settings
    zeek_thirdparty_module_settings
    thirdparty_openssl
    thirdparty_caf_io
  )

  target_compile_features(thirdparty_caf_openssl INTERFACE cxx_std_11)

  target_include_directories(thirdparty_caf_openssl SYSTEM PUBLIC
    "${library_root}"
  )
endfunction()

cafMain()
