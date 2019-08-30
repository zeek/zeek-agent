# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)

function(zeekRemoteTests)
  set(library_list
    thirdparty_caf
    thirdparty_broker
  )

  set(target_name_list
    broker_manager
    query_manager
  )

  getTargetSourceFileList(zeek-remote zeek_remote_source_file_list)

  foreach(target_name ${target_name_list})
    addZeekTest(
      NAME
      "${target_name}"

      TARGET
        zeek-remote

      SOURCES
        "${target_name}.cpp"

      LINK_LIBRARIES
        ${library_list}

      INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src"
    )
  endforeach()
endfunction()

zeekRemoteTests()
