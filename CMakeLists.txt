# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)
project(osquery-zeek)

include(cmake/utils.cmake)

function(osqueryZeekMain)
  importBroker()
  importCaf()

  add_subdirectory("zeek-remote")
  add_subdirectory("zeek-extension")
endfunction()

osqueryZeekMain()
