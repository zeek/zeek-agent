cmake_minimum_required(VERSION 3.14)

if("${CMAKE_BUILD_TYPE}" STREQUAL "")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
endif()

option(ZEEK_AGENT_ENABLE_TESTS "Set to ON to build the tests")
option(ZEEK_AGENT_ENABLE_INSTALL "Set to ON to generate the install directives")
option(ZEEK_AGENT_ENABLE_SANITIZERS "Set to ON to enable sanitizers. Only available when compiling with Clang")
set(ZEEK_AGENT_TOOLCHAIN_PATH "" CACHE PATH "Toolchain path")

if(NOT "${ZEEK_AGENT_TOOLCHAIN_PATH}" STREQUAL "")
  if(NOT EXISTS "${ZEEK_AGENT_TOOLCHAIN_PATH}")
    message(FATAL_ERROR "zeek-agent: The specified toolchain path is not valid: ${ZEEK_AGENT_TOOLCHAIN_PATH}")
  endif()

  message(STATUS "zeek-agent: Using toolchain path '${ZEEK_AGENT_TOOLCHAIN_PATH}'")

  set(CMAKE_C_COMPILER "${ZEEK_AGENT_TOOLCHAIN_PATH}/usr/bin/clang" CACHE PATH "Path to the C compiler" FORCE)
  set(CMAKE_CXX_COMPILER "${ZEEK_AGENT_TOOLCHAIN_PATH}/usr/bin/clang++" CACHE PATH "Path to the C++ compiler" FORCE)

  set(CMAKE_SYSROOT "${ZEEK_AGENT_TOOLCHAIN_PATH}" CACHE PATH "CMake sysroot for find_package scripts")
  set(default_libcpp_option_value ON)

else()
  set(default_libcpp_option_value OFF)
endif()

option(ZEEK_AGENT_ENABLE_LIBCPP "Set to ON to enable linking against libc++ and libc++abi" ${default_libcpp_option_value})
