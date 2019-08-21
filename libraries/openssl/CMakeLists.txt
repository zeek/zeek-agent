# Copyright (c) 2014-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the Apache 2.0 license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# You may select, at your option, one of the above-listed licenses.

cmake_minimum_required(VERSION 3.10)

function(opensslMain)
  # todo(alessandro): Remove this once the extension is migrated to the
  # osquery 4.x SDK
  add_library(thirdparty_openssl STATIC IMPORTED GLOBAL)
  set_target_properties(thirdparty_openssl PROPERTIES IMPORTED_LOCATION
    /usr/local/osquery/lib/libssl.a
  )

  target_include_directories(thirdparty_openssl SYSTEM INTERFACE
    /usr/local/osquery/include
  )
endfunction()

opensslMain()
