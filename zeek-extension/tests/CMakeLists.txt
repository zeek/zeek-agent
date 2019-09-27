#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

cmake_minimum_required(VERSION 3.10)

function(zeekExtensionTests)
  set(library_list
    zeek-remote
  )

  set(target_name_list
    configuration_checker
  )

  foreach(target_name ${target_name_list})
    addZeekTest(
      NAME
      "${target_name}"

      SOURCES
        "${target_name}.cpp"

      TARGET
        osquery-zeek

      LINK_LIBRARIES
        ${library_list}

      INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/../src"
    )
  endforeach()
endfunction()

zeekExtensionTests()
