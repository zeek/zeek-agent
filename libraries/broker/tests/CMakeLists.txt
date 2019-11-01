# -- Global test harness setup ------------------------------------------------

set(BROKER_TEST_TIMEOUT 20)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/cpp)

# -- C++ ----------------------------------------------------------------------

set(tests
  cpp/backend.cc
  cpp/core.cc
  cpp/data.cc
  cpp/detail/data_generator.cc
  cpp/detail/generator_file_writer.cc
  cpp/detail/meta_command_writer.cc
  cpp/detail/meta_data_writer.cc
  cpp/integration.cc
  cpp/master.cc
  cpp/publisher.cc
  cpp/radix_tree.cc
  cpp/ssl.cc
  cpp/status_subscriber.cc
  cpp/store.cc
  cpp/subscriber.cc
  cpp/test.cc
  cpp/topic.cc
  cpp/zeek.cc
)

# Setup correct broker library (static/shared).
if (ENABLE_SHARED)
  set(libbroker broker)
else ()
  set(libbroker broker_static)
endif ()
add_executable(broker-test ${tests})
target_link_libraries(broker-test ${libbroker})

set(BROKER_TEST_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

macro(make_cpp_test suite)
  string(REPLACE " " "_" test_name ${suite})
  set(test_verbosity 4)
  if (${test_name} STREQUAL radix_tree)
    set(test_verbosity 3)  # otherwise it just produces way too much output
  endif ()
  add_test(NAME ${test_name} COMMAND broker-test -v ${test_verbosity} -s "${suite}" ${ARGN})
  set_tests_properties(${test_name} PROPERTIES TIMEOUT ${BROKER_TEST_TIMEOUT})
  set_tests_properties(${test_name} PROPERTIES ENVIRONMENT
                       "BROKER_TEST_DIR=${BROKER_TEST_DIR}")
endmacro()

# Find all test suites.
foreach(test ${tests})
  file(STRINGS ${test} contents)
  foreach(line ${contents})
    if ("${line}" MATCHES "SUITE")
      string(REGEX REPLACE ".* SUITE (.*)" "\\1" suite ${line})
      list(APPEND suites ${suite})
    endif()
  endforeach()
endforeach()
list(REMOVE_DUPLICATES suites)

foreach(suite ${suites})
  make_cpp_test("${suite}")
endforeach ()

# -- Python -------------------------------------------------------------------

if (BROKER_PYTHON_BINDINGS)
  configure_file(${CMAKE_CURRENT_SOURCE_DIR}/python/run-zeek.in
                 ${CMAKE_CURRENT_BINARY_DIR}/python/run-zeek)

  macro(make_python_test name)
    set(script ${CMAKE_CURRENT_SOURCE_DIR}/python/${name}.py)
    set(test_name python-${name})
    add_test(NAME ${test_name}
             COMMAND ${PYTHON_EXECUTABLE} ${script}
             WORKING_DIRECTORY ${BROKER_PYTHON_STAGING_DIR})
    set_tests_properties(${test_name} PROPERTIES TIMEOUT ${BROKER_TEST_TIMEOUT})
    set_tests_properties(${test_name} PROPERTIES ENVIRONMENT
                         "PYTHONPATH=${BROKER_PYTHON_STAGING_DIR};BROKER_TEST_DIR=${BROKER_TEST_DIR}")
  endmacro()

  if (ZEEK_FOUND)
    make_python_test(zeek)
  endif ()

  make_python_test(communication)
  make_python_test(data)
  make_python_test(forwarding)
  make_python_test(ssl)
  make_python_test(store)
  make_python_test(topic)
endif ()

## -- Benchmark

add_executable(broker-benchmark benchmark/broker-benchmark.cc)
target_link_libraries(broker-benchmark ${libbroker})

add_executable(broker-stream-benchmark benchmark/broker-stream-benchmark.cc)
target_link_libraries(broker-stream-benchmark ${libbroker})

