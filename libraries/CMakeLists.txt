cmake_minimum_required(VERSION 3.14)

function(zeekAgentLibraries)
  add_library(zeek_agent_libraries_settings INTERFACE)
  target_compile_options(zeek_agent_libraries_settings INTERFACE
    -Wno-error
  )

  add_subdirectory("catch2")
  add_subdirectory("audit")
  add_subdirectory("broker")
  add_subdirectory("xxhash")

  # If we are being built under osquery, then we may already have
  # some of these libraries available

  if(NOT TARGET thirdparty_sqlite)
    add_subdirectory("sqlite")
  endif()

  if(NOT TARGET thirdparty_rapidjson)
    add_subdirectory("rapidjson")
  endif()

  if(NOT TARGET thirdparty_zlib)
    # zlib is marked as EXCLUDE_FROM_ALL and will only be build
    # if the OpenSSL library is build from source
    add_subdirectory("zlib")
  endif()

  # OpenSSL is only built if we are building zeek-agent alone with
  # the custom toolchain
  if(NOT TARGET thirdparty_openssl AND NOT "${ZEEK_AGENT_TOOLCHAIN_PATH}" STREQUAL "")
    add_subdirectory("openssl")

  else()
    find_package(OpenSSL REQUIRED)

    add_library(thirdparty_openssl INTERFACE)
    target_link_libraries(thirdparty_openssl INTERFACE
      OpenSSL::SSL
      OpenSSL::Crypto
    )
  endif()
endfunction()

zeekAgentLibraries()
