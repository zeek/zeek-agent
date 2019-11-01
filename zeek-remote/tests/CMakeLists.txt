#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.10)

function(zeekRemoteTests)
  set(library_list
    broker
  )

  set(target_name_list
    broker_manager
    query_manager
  )

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

        # todo: Uncomment this when moving to osquery 4.x
        # thirdparty_rapidjson

      INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/../include"
        "${CMAKE_CURRENT_SOURCE_DIR}/../src"
    )
  endforeach()
endfunction()

zeekRemoteTests()
