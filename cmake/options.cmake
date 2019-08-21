cmake_minimum_required(VERSION 3.14)

if("${CMAKE_BUILD_TYPE}" STREQUAL "")
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Build type" FORCE)
endif()

option(ZEEK_AGENT_ENABLE_TESTS "Set to ON to build the tests")
option(ZEEK_AGENT_ENABLE_INSTALL "Set to ON to generate the install directives")
option(ZEEK_AGENT_ENABLE_SANITIZERS "Set to ON to enable sanitizers. Only available when compiling with Clang")
