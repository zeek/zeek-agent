# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)

option(ZEEK_BUILD_TESTING "Set to ON to enable tests" ON)

# todo: Remove this once the extension is ported to osquery 4.x
function(getOptionsFromEnvironment)
  if(DEFINED ENV{ZEEK_BUILD_TESTING})
    set(tests_enabled ON)
  else()
    set(tests_enabled OFF)
  endif()

  set(ZEEK_BUILD_TESTING ${tests_enabled} CACHE BOOL "" FORCE)
endfunction()

getOptionsFromEnvironment()
