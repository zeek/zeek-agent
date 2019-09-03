# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

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
