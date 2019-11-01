# -- Project Setup ------------------------------------------------------------

project(broker C CXX)
cmake_minimum_required(VERSION 2.8.12)
include(cmake/CommonCMakeConfig.cmake)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/lib)

if ( ENABLE_CCACHE )
  find_program(CCACHE_PROGRAM ccache)

  if ( NOT CCACHE_PROGRAM )
    message(FATAL_ERROR "ccache not found")
  endif ()

  message(STATUS "Using ccache: ${CCACHE_PROGRAM}")
  set(CMAKE_C_COMPILER_LAUNCHER   ${CCACHE_PROGRAM})
  set(CMAKE_CXX_COMPILER_LAUNCHER ${CCACHE_PROGRAM})
endif ()

# -- Dependencies -------------------------------------------------------------
if ( CAF_ROOT_DIR )
  find_package(CAF COMPONENTS openssl test io core REQUIRED)
  set(caf_dir    "${CAF_LIBRARY_CORE}")
  set(caf_config "${CAF_INCLUDE_DIR_CORE}/caf/config.hpp")
  get_filename_component(caf_dir ${caf_dir} PATH)

  if (EXISTS "${caf_dir}/../libcaf_core")
    get_filename_component(caf_dir ${caf_dir} PATH)
  else ()
    set(caf_dir "${CAF_INCLUDE_DIR_CORE}")
  endif ()
else ()

  include(ExternalProject)
  set(caf_src     "${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/caf")
  set(caf_ep      "${CMAKE_CURRENT_BINARY_DIR}/caf-ep")
  set(caf_build   "${CMAKE_CURRENT_BINARY_DIR}/caf-build")
  set(caf_dir     "${caf_src}")
  set(caf_install "${CMAKE_INSTALL_PREFIX}")
  set(shared_ext  "${CMAKE_SHARED_LIBRARY_SUFFIX}")
  set(static_ext  "${CMAKE_STATIC_LIBRARY_SUFFIX}")
  set(caf_config  "${caf_src}/libcaf_core/caf/config.hpp")

  if ( ${CMAKE_VERSION} VERSION_LESS "3.2.0" )
    # Build byproducts is just required by the Ninja generator
    # though it's not available before CMake 3.2 ...
    if ( ${CMAKE_GENERATOR} STREQUAL Ninja )
      message(FATAL_ERROR "Ninja generator requires CMake >= 3.2")
    endif ()

    set(build_byproducts_arg)
  else ()
    if ( ENABLE_STATIC OR ENABLE_STATIC_ONLY )
        set(build_byproducts_arg BUILD_BYPRODUCTS
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_core_static${static_ext}
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_io_static${static_ext}
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_openssl_static${static_ext}
        )
    else ()
        set(build_byproducts_arg BUILD_BYPRODUCTS
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_core${shared_ext}
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_io${shared_ext}
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_openssl${shared_ext}
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_core_static${static_ext}
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_io_static${static_ext}
            ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_openssl_static${static_ext}
        )
      endif()
  endif ()

  ExternalProject_Add(project_caf
    PREFIX            "${caf_ep}"
    BINARY_DIR        "${caf_build}"
    DOWNLOAD_COMMAND  ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    ${build_byproducts_arg}
  )

  if ( ${CMAKE_VERSION} VERSION_LESS "3.4.0" )
    set(use_terminal_arg)
  else ()
    set(use_terminal_arg USES_TERMINAL 1)
  endif ()

  ExternalProject_Add_Step(project_caf project_caf_build_step
    COMMAND ${CMAKE_MAKE_PROGRAM}
    COMMENT "Building CAF"
    WORKING_DIRECTORY ${caf_build}
    ALWAYS 1
    ${use_terminal_arg}
  )

  install(CODE "execute_process(
    COMMAND ${CMAKE_MAKE_PROGRAM} install
    WORKING_DIRECTORY ${caf_build}
    )"
  )

  if ( CMAKE_TOOLCHAIN_FILE )
    set(toolchain_arg -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE})
  else ()
    set(toolchain_arg)
  endif ()

  find_package(OpenSSL REQUIRED)
  get_filename_component(derived_openssl_root_dir ${OPENSSL_INCLUDE_DIR}
                         DIRECTORY)

  if ( CMAKE_C_COMPILER_LAUNCHER )
    set(cmake_c_compiler_launcher_arg
        -DCMAKE_C_COMPILER_LAUNCHER:path=${CMAKE_C_COMPILER_LAUNCHER})
  else ()
    set(cmake_c_compiler_launcher_arg)
  endif ()

  if ( CMAKE_CXX_COMPILER_LAUNCHER )
    set(cmake_cxx_compiler_launcher_arg
        -DCMAKE_CXX_COMPILER_LAUNCHER:path=${CMAKE_CXX_COMPILER_LAUNCHER})
  else ()
    set(cmake_cxx_compiler_launcher_arg)
  endif ()

  if ( NOT CAF_LOG_LEVEL )
    set(CAF_LOG_LEVEL "QUIET")
  endif ()

  execute_process(
      COMMAND
        ${CMAKE_COMMAND}
        -G${CMAKE_GENERATOR}
        ${toolchain_arg}
        ${cmake_c_compiler_launcher_arg}
        ${cmake_cxx_compiler_launcher_arg}
        -DCAF_LOG_LEVEL:string=${CAF_LOG_LEVEL}
        -DOPENSSL_ROOT_DIR:path=${derived_openssl_root_dir}
        -DCAF_NO_UNIT_TESTS:bool=yes
        -DCAF_NO_EXAMPLES:bool=yes
        -DCAF_NO_TOOLS:bool=yes
        -DCAF_NO_PYTHON:bool=yes
        -DCAF_NO_OPENCL:bool=yes
        -DCAF_BUILD_STATIC:bool=${ENABLE_STATIC}
        -DCAF_BUILD_STATIC_ONLY:bool=${ENABLE_STATIC_ONLY}
        # Sticking CAF libs in the same output dir as libbroker is a bit of a
        # hack until CMake 3.8, which has BUILD_RPATH that can instead be set
        # on libbroker.  The problem here is that broker unit tests will fail
        # if linker can't locate CAF libs (e.g. via build-tree RPATH).
        -DCMAKE_LIBRARY_OUTPUT_DIRECTORY:path=${CMAKE_LIBRARY_OUTPUT_DIRECTORY}
        -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY:path=${CMAKE_ARCHIVE_OUTPUT_DIRECTORY}
        -DCMAKE_BUILD_TYPE:string=${CMAKE_BUILD_TYPE}
        -DCMAKE_INSTALL_PREFIX:path=${caf_install}
        ${caf_src}
      WORKING_DIRECTORY ${caf_build}
      RESULT_VARIABLE caf_cmake_result
      ERROR_VARIABLE CAF_CMAKE_OUTPUT
      OUTPUT_VARIABLE CAF_CMAKE_OUTPUT
      ERROR_STRIP_TRAILING_WHITESPACE
      OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  message("\n********** Begin CAF External Project CMake Output ************")
  message("\n${CAF_CMAKE_OUTPUT}")
  message("\n*********** End CAF External Project CMake Output *************")
  message("\n")

  if (caf_cmake_result)
    message(FATAL_ERROR "CAF CMake configuration failed")
  endif ()

  if ( ENABLE_STATIC OR ENABLE_STATIC_ONLY )
    add_library(libcaf_openssl_static STATIC IMPORTED GLOBAL)
    add_library(libcaf_core_static STATIC IMPORTED GLOBAL)
    add_library(libcaf_io_static STATIC IMPORTED GLOBAL)
    set_property(TARGET libcaf_core_static PROPERTY IMPORTED_LOCATION
                 ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_core_static${static_ext})
    set_property(TARGET libcaf_io_static PROPERTY IMPORTED_LOCATION
                 ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_io_static${static_ext})
    set_property(TARGET libcaf_openssl_static PROPERTY IMPORTED_LOCATION
                 ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_openssl_static${static_ext})
  else ()
    add_library(libcaf_core_shared SHARED IMPORTED GLOBAL)
    add_library(libcaf_io_shared SHARED IMPORTED GLOBAL)
    add_library(libcaf_openssl_shared SHARED IMPORTED GLOBAL)
    set_property(TARGET libcaf_core_shared PROPERTY IMPORTED_LOCATION
                 ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_core${shared_ext})
    set_property(TARGET libcaf_io_shared PROPERTY IMPORTED_LOCATION
                 ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_io${shared_ext})
    set_property(TARGET libcaf_openssl_shared PROPERTY IMPORTED_LOCATION
                 ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libcaf_openssl${shared_ext})
  endif ()
  if ( ENABLE_STATIC OR ENABLE_STATIC_ONLY )
    add_dependencies(libcaf_openssl_static project_caf)
    add_dependencies(libcaf_io_static project_caf)
    add_dependencies(libcaf_core_static project_caf)
  else()
    add_dependencies(libcaf_core_shared project_caf)
    add_dependencies(libcaf_io_shared project_caf)
    add_dependencies(libcaf_openssl_shared project_caf)
  endif()

  set(CAF_FOUND true)
  if ( ENABLE_STATIC OR ENABLE_STATIC_ONLY )
    set(CAF_LIBRARIES
			libcaf_openssl_static libcaf_io_static libcaf_core_static
			CACHE STRING "CAF libs" FORCE)
  else ()
    set(CAF_LIBRARIES
      libcaf_core_shared libcaf_io_shared libcaf_openssl_shared
      CACHE STRING "CAF libs" FORCE)
  endif ()

  set(CAF_INCLUDE_DIRS
      "${caf_src}/libcaf_core"
      "${caf_build}/libcaf_core"
      "${caf_src}/libcaf_io"
      "${caf_src}/libcaf_openssl"
      "${caf_src}/libcaf_test"
      CACHE STRING "CAF includes" FORCE)

  set(CAF_INCLUDE_DIR_CORE
      ${caf_src}/libcaf_core
      ${caf_build}/libcaf_core
      CACHE PATH "CAF core headers" FORCE)
  set(CAF_INCLUDE_DIR_IO
      "${caf_src}/libcaf_io" CACHE PATH "CAF io headers" FORCE)
  set(CAF_INCLUDE_DIR_OPENSSL
      "${caf_src}/libcaf_openssl" CACHE PATH "CAF openssl headers" FORCE)
endif ()

file(READ "${caf_config}" caf_config_hpp)
string(REGEX MATCH "#define CAF_VERSION [0-9]+"
       caf_version_line "${caf_config_hpp}")
string(REGEX MATCH "[0-9]+" caf_version_int "${caf_version_line}")
math(EXPR caf_version_major "${caf_version_int} / 10000")
math(EXPR caf_version_minor "( ${caf_version_int} / 100) % 100")
math(EXPR caf_version_patch "${caf_version_int} % 100")
set(CAF_VERSION
    "${caf_version_major}.${caf_version_minor}.${caf_version_patch}")

set(CAF_VERSION_REQUIRED 0.15.5)

if (CAF_VERSION VERSION_LESS ${CAF_VERSION_REQUIRED})
  message(FATAL_ERROR "Broker requires at least CAF version"
    " ${CAF_VERSION_REQUIRED}, detected version: ${CAF_VERSION}")
endif ()

include_directories(BEFORE ${CAF_INCLUDE_DIRS})
set(LINK_LIBS ${LINK_LIBS} ${CAF_LIBRARIES})

# OpenSSL
find_package(OpenSSL REQUIRED)
set(LINK_LIBS ${LINK_LIBS} ${OPENSSL_LIBRARIES})

# RocksDB
find_package(RocksDB)
if (ROCKSDB_FOUND)
  set(BROKER_HAVE_ROCKSDB true)
  include_directories(BEFORE ${ROCKSDB_INCLUDE_DIRS})
  set(LINK_LIBS ${LINK_LIBS} ${ROCKSDB_LIBRARIES})
  set(OPTIONAL_SRC ${OPTIONAL_SRC} src/detail/rocksdb_backend.cc)
endif ()

# -- libroker -----------------------------------------------------------------

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" BROKER_VERSION LIMIT_COUNT 1)
string(REPLACE "." " " _version_numbers ${BROKER_VERSION})
separate_arguments(_version_numbers)
list(GET _version_numbers 0 BROKER_VERSION_MAJOR)
list(GET _version_numbers 1 BROKER_VERSION_MINOR)

# The SO number shall increase only if binary interface changes.
set(BROKER_SOVERSION 2)
set(ENABLE_SHARED true)

if (ENABLE_STATIC_ONLY)
  set(ENABLE_STATIC true)
  set(ENABLE_SHARED false)
endif ()

# -- compiler -----------------------------------------------------------------

if (APPLE)
  set(BROKER_APPLE true)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
  set(BROKER_LINUX true)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
  set(BROKER_FREEBSD)
endif ()

include(RequireCXX11)

# Mac OS ignores -pthread but other platforms require it
if (NOT BROKER_APPLE)
  set(EXTRA_FLAGS "${EXTRA_FLAGS} -pthread")
endif ()

# Increase warnings.
set(EXTRA_FLAGS "${EXTRA_FLAGS} -Wall -Wno-unused -pedantic")

# Increase maximum number of instantiations.
set(EXTRA_FLAGS "${EXTRA_FLAGS} -ftemplate-depth=512")

# Reduce the number of template instantiations shown in backtrace.
set(EXTRA_FLAGS "${EXTRA_FLAGS} -ftemplate-backtrace-limit=3")

if (ENABLE_ADDRESS_SANITIZER)
  set(EXTRA_FLAGS "${EXTRA_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
  # Some Linux distributions have apparently cannot pick the right linker
  # properly. See: http://stackoverflow.com/q/37603238/1170277
  if (BROKER_LINUX)
    set(EXTRA_FLAGS "${EXTRA_FLAGS} -fuse-ld=gold")
  endif ()
endif(ENABLE_ADDRESS_SANITIZER)

# Append our extra flags to the existing value of CXXFLAGS.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_FLAGS}")

install(DIRECTORY include/broker DESTINATION include FILES_MATCHING PATTERN "*.hh")

include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(BEFORE ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty)

set_source_files_properties(3rdparty/sqlite3.c PROPERTIES COMPILE_FLAGS
                            -DSQLITE_OMIT_LOAD_EXTENSION)

include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/src/config.hh.in
               ${CMAKE_CURRENT_BINARY_DIR}/include/broker/config.hh)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/include/broker/config.hh DESTINATION include/broker)

set(BROKER_SRC
  ${OPTIONAL_SRC}
  3rdparty/sqlite3.c
  src/address.cc
  src/configuration.cc
  src/core_actor.cc
  src/data.cc
  src/defaults.cc
  src/detail/abstract_backend.cc
  src/detail/clone_actor.cc
  src/detail/core_policy.cc
  src/detail/data_generator.cc
  src/detail/filesystem.cc
  src/detail/flare.cc
  src/detail/flare_actor.cc
  src/detail/generator_file_reader.cc
  src/detail/generator_file_writer.cc
  src/detail/make_backend.cc
  src/detail/master_actor.cc
  src/detail/master_resolver.cc
  src/detail/memory_backend.cc
  src/detail/meta_command_writer.cc
  src/detail/meta_data_writer.cc
  src/detail/network_cache.cc
  src/detail/prefix_matcher.cc
  src/detail/sqlite_backend.cc
  src/endpoint.cc
  src/error.cc
  src/internal_command.cc
  src/mailbox.cc
  src/network_info.cc
  src/peer_status.cc
  src/port.cc
  src/publisher.cc
  src/status.cc
  src/status_subscriber.cc
  src/store.cc
  src/subnet.cc
  src/subscriber.cc
  src/time.cc
  src/topic.cc
  src/version.cc
)

include(TestBigEndian)
test_big_endian(BROKER_BIG_ENDIAN)

include(CheckIncludeFiles)
set(CMAKE_REQUIRED_FLAGS -msse2)
check_include_files(emmintrin.h HAVE_SSE2)
set(CMAKE_REQUIRED_FLAGS)

if (HAVE_SSE2)
  add_definitions(-DBROKER_USE_SSE2 -msse2)
endif ()

set(atomic_64bit_ops_test "
  #include <atomic>
  struct s64 { char a, b, c, d, e, f, g, h; };
  int main() { std::atomic<s64> x; x.store({}); x.load(); return 0; }
")
check_cxx_source_compiles("${atomic_64bit_ops_test}" atomic64_builtin)

if ( NOT atomic64_builtin )
  set(CMAKE_REQUIRED_LIBRARIES atomic)
  check_cxx_source_compiles("${atomic_64bit_ops_test}" atomic64_with_lib)
  set(CMAKE_REQUIRED_LIBRARIES)

  if ( atomic64_with_lib )
    set(LINK_LIBS ${LINK_LIBS} atomic)
  else ()
    # Guess we'll find out for sure when we compile/link.
    message(WARNING "build may fail due to missing 64-bit atomic support")
  endif ()
endif ()

if (NOT INSTALL_LIB_DIR)
  set(INSTALL_LIB_DIR ${CMAKE_INSTALL_PREFIX}/lib)
endif ()

if (ENABLE_SHARED)
  add_library(broker SHARED ${BROKER_SRC})
  set_target_properties(broker PROPERTIES
                        SOVERSION ${BROKER_SOVERSION}
                        VERSION ${BROKER_VERSION_MAJOR}.${BROKER_VERSION_MINOR}
                        MACOSX_RPATH true
                        OUTPUT_NAME broker)
  target_link_libraries(broker ${LINK_LIBS})
  install(TARGETS broker DESTINATION ${INSTALL_LIB_DIR})
endif ()

if (ENABLE_STATIC)
  add_library(broker_static STATIC ${BROKER_SRC})
  set_target_properties(broker_static PROPERTIES OUTPUT_NAME broker)
  if (NOT DISABLE_PYTHON_BINDINGS)
    set_target_properties(broker_static PROPERTIES POSITION_INDEPENDENT_CODE ON)
  endif()
  target_link_libraries(broker_static ${LINK_LIBS})
  install(TARGETS broker_static DESTINATION ${INSTALL_LIB_DIR})
endif ()

# -- Tools --------------------------------------------------------------------

macro(add_tool name)
  add_executable(${name} src/${name}.cc ${ARGN})
  if (ENABLE_SHARED)
    target_link_libraries(${name} ${LINK_LIBS} broker)
    add_dependencies(${name} broker)
  else()
    target_link_libraries(${name} ${LINK_LIBS} broker_static)
    add_dependencies(${name} broker_static)
  endif()
endmacro()

add_tool(broker-pipe)
add_tool(broker-node)

# -- Bindings -----------------------------------------------------------------

if (NOT DISABLE_PYTHON_BINDINGS)
  find_package(PythonInterp)
  if (NOT PYTHONINTERP_FOUND)
    message(STATUS "Skipping Python bindings: Python interpreter not found")
  endif ()

  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/bindings/python/3rdparty/pybind11/CMakeLists.txt")
    message(WARNING "Skipping Python bindings: pybind11 submodule not available")
    set(PYTHONINTERP_FOUND false)
  endif ()

  if (${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR} VERSION_LESS 2.7)
    message(WARNING "Skipping Python bindings: Python 2.7 or Python 3 required")
    set(PYTHONINTERP_FOUND false)
  endif ()

  find_package(PythonDev)
  if (PYTHONDEV_FOUND)
    # The standard PythonLibs package puts its includes at PYTHON_INCLUDE_DIRS.
    set(PYTHON_INCLUDE_DIRS ${PYTHON_INCLUDE_DIR})
  else ()
    message(STATUS
            "Skipping Python bindings: Python includes/libraries not found")
  endif ()

  if (PYTHONINTERP_FOUND AND PYTHONDEV_FOUND)
    set (BROKER_PYTHON_BINDINGS true)
    set (BROKER_PYTHON_STAGING_DIR ${CMAKE_CURRENT_BINARY_DIR}/python)
    add_subdirectory(bindings/python)
  endif ()
endif ()

# -- Zeek ---------------------------------------------------------------------

if (NOT "${ZEEK_EXECUTABLE}" STREQUAL "")
    set(ZEEK_FOUND true)
    set(ZEEK_FOUND_MSG "${ZEEK_EXECUTABLE}")
else ()
    set(ZEEK_FOUND false)
    find_file(ZEEK_PATH_DEV zeek-path-dev.sh PATHS ${CMAKE_CURRENT_BINARY_DIR}/../../../build NO_DEFAULT_PATH)
    if (EXISTS ${ZEEK_PATH_DEV})
      set(ZEEK_FOUND true)
      set(ZEEK_FOUND_MSG "${ZEEK_PATH_DEV}")
    endif ()
endif ()

# -- Unit Tests ---------------------------------------------------------------

if ( NOT BROKER_DISABLE_TESTS )
  enable_testing()
  add_subdirectory(tests)
endif ()

# -- Documentation ------------------------------------------------------------

if (NOT BROKER_DISABLE_DOCS)
  add_subdirectory(doc)
endif ()

# -- Build Summary ------------------------------------------------------------

string(TOUPPER ${CMAKE_BUILD_TYPE} BuildType)

macro(display test desc summary)
  if ( ${test} )
    set(${summary} ${desc})
  else ()
    set(${summary} no)
  endif()
endmacro()

display(ENABLE_SHARED yes shared_summary)
display(ENABLE_STATIC yes static_summary)
display(CAF_FOUND "${caf_dir} (${CAF_VERSION})" caf_summary)
display(ROCKSDB_FOUND "${ROCKSDB_INCLUDE_DIRS}" rocksdb_summary)
display(BROKER_PYTHON_BINDINGS yes python_summary)
display(ZEEK_FOUND "${ZEEK_FOUND_MSG}" zeek_summary)

set(summary
    "==================|  Broker Config Summary  |===================="
    "\nVersion:         ${BROKER_VERSION}"
    "\nSO version:      ${BROKER_SOVERSION}"
    "\n"
    "\nBuild Type:      ${CMAKE_BUILD_TYPE}"
    "\nInstall prefix:  ${CMAKE_INSTALL_PREFIX}"
    "\nLibrary prefix:  ${INSTALL_LIB_DIR}"
    "\nShared libs:     ${shared_summary}"
    "\nStatic libs:     ${static_summary}"
    "\n"
    "\nCC:              ${CMAKE_C_COMPILER}"
    "\nCFLAGS:          ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${BuildType}}"
    "\nCXX:             ${CMAKE_CXX_COMPILER}"
    "\nCXXFLAGS:        ${CMAKE_CXX_FLAGS} ${CMAKE_CXX_FLAGS_${BuildType}}"
    "\n"
    "\nCAF:             ${caf_summary}"
    "\nRocksDB:         ${rocksdb_summary}"
    "\nPython bindings: ${python_summary}"
    "\nZeek:            ${zeek_summary}"
    "\n=================================================================")

message("\n" ${summary} "\n")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/config.summary ${summary})

include(UserChangedWarning)
