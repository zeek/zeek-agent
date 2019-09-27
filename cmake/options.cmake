#
# Copyright (c) 2019-present, The International Computer Science Institute
# All rights reserved.
#
# This source code is licensed in accordance with the terms specified in
# the LICENSE file found in the root directory of this source tree.
#

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
