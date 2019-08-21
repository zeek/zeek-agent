# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)

function(brokerMain)
  generateBroker()
endfunction()

function(generateBroker)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")

  add_library(thirdparty_broker
    "${library_root}/src/address.cc"
    "${library_root}/src/configuration.cc"
    "${library_root}/src/core_actor.cc"
    "${library_root}/src/data.cc"
    "${library_root}/src/endpoint.cc"
    "${library_root}/src/error.cc"
    "${library_root}/src/status_subscriber.cc"
    "${library_root}/src/internal_command.cc"
    "${library_root}/src/mailbox.cc"
    "${library_root}/src/network_info.cc"
    "${library_root}/src/peer_status.cc"
    "${library_root}/src/port.cc"
    "${library_root}/src/publisher.cc"
    "${library_root}/src/status.cc"
    "${library_root}/src/store.cc"
    "${library_root}/src/subnet.cc"
    "${library_root}/src/subscriber.cc"
    "${library_root}/src/time.cc"
    "${library_root}/src/topic.cc"
    "${library_root}/src/version.cc"
  
    "${library_root}/src/detail/abstract_backend.cc"
    "${library_root}/src/detail/clone_actor.cc"
    "${library_root}/src/detail/core_policy.cc"
    "${library_root}/src/detail/filesystem.cc"
    "${library_root}/src/detail/flare.cc"
    "${library_root}/src/detail/flare_actor.cc"
    "${library_root}/src/detail/make_backend.cc"
    "${library_root}/src/detail/master_actor.cc"
    "${library_root}/src/detail/master_resolver.cc"
    "${library_root}/src/detail/memory_backend.cc"
    "${library_root}/src/detail/network_cache.cc"
    "${library_root}/src/detail/prefix_matcher.cc"
    "${library_root}/src/detail/sqlite_backend.cc"
    "${library_root}/src/detail/rocksdb_backend.cc"
  )

  target_link_libraries(thirdparty_broker PUBLIC
    zeek_common_settings
    thirdparty_caf
    thirdparty_sqlite
    thirdparty_rocksdb
  )

  target_include_directories(thirdparty_broker PRIVATE
    "${library_root}/src/detail"
  )

  target_include_directories(thirdparty_broker SYSTEM PUBLIC
    "${library_root}"
  )

  target_compile_features(thirdparty_broker INTERFACE cxx_std_11)

  target_compile_definitions(thirdparty_broker PRIVATE
    BROKER_HAVE_ROCKSDB=1
  )
endfunction()

brokerMain()
