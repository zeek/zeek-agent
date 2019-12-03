cmake_minimum_required(VERSION 3.14)

function(generateSettingsTarget)
  if("${CMAKE_BUILD_TYPE}" STREQUAL "")
    message(FATAL_ERROR "Invalid build type specified: ${CMAKE_BUILD_TYPE}")
  endif()

  add_library(zeek_agent_common_settings INTERFACE)

  set(common_compilation_flags
    ${ZEEK_AGENT_COMMON_COMPILATION_FLAGS}
  )

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    list(APPEND zeek_agent_common_settings -g3)
  endif()

  if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
    list(APPEND zeek_agent_common_settings -O0)
  else()
    list(APPEND zeek_agent_common_settings -O3)
  endif()

  target_compile_options(zeek_agent_common_settings INTERFACE
    ${common_compilation_flags}
  )

  add_library(zeek_agent_c_settings INTERFACE)
  target_link_libraries(zeek_agent_c_settings INTERFACE zeek_agent_common_settings)

  add_library(zeek_agent_cxx_settings INTERFACE)
  target_link_libraries(zeek_agent_cxx_settings INTERFACE zeek_agent_common_settings)

  target_compile_features(zeek_agent_cxx_settings INTERFACE
    cxx_std_17
  )

  if(ZEEK_AGENT_ENABLE_LIBCPP)
    target_compile_options(zeek_agent_cxx_settings INTERFACE
      -stdlib=libc++
    )

    target_link_options(zeek_agent_cxx_settings INTERFACE
      -stdlib=libc++
    )

    target_link_libraries(zeek_agent_cxx_settings INTERFACE
      libc++abi.a
    )
  endif()

  configureClangSanitizers("zeek_agent_common_settings")
endfunction()

function(configureClangSanitizers target_name)
  if(NOT ZEEK_AGENT_ENABLE_SANITIZERS)
    message(STATUS "zeek-agent: Sanitizers are disabled")
    return()
  endif()

  set(sanitizer_flag_list
    -fno-omit-frame-pointer
    -fsanitize=address,undefined
  )

  if(NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" AND NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang")
    message(STATUS "zeek-agent: Sanitizers are disabled (the current compiler is not compatible)")
    return()
  endif()

  target_compile_options(zeek_agent_common_settings INTERFACE
    ${sanitizer_flag_list}
  )

  target_link_options(zeek_agent_common_settings INTERFACE
    ${sanitizer_flag_list}
  )

  if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" AND NOT "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
    message(WARNING "zeek-agent: Sanitizers work best with debug symbols!")
  endif()

  message(STATUS "zeek-agent: Sanitizers are enabled")
endfunction()
