# The internal module, which is wrapped by Python code.
add_library(_broker MODULE _broker.cpp data.cpp enums.cpp store.cpp zeek.cpp)

# Stage the Python wrapper along with the internal module in the public
# "broker" module.
set (BROKER_PYTHON_MODULE_DIR ${BROKER_PYTHON_STAGING_DIR}/broker)
set_target_properties(_broker PROPERTIES
                      OUTPUT_NAME "_broker"
                      LIBRARY_OUTPUT_DIRECTORY ${BROKER_PYTHON_MODULE_DIR}
                      # By setting an empty prefix, we can invoke the Python
                      # executable in the same path as the module. Then
                      # 'import _broker' Just Works.
                      PREFIX "")

# Stage Python scripts.
add_custom_target(python-scripts-stage
                  COMMAND ${CMAKE_COMMAND} -E copy_directory
                    ${CMAKE_CURRENT_SOURCE_DIR}/broker
                    ${BROKER_PYTHON_MODULE_DIR}
                  COMMENT
                    "Staging Python scripts in ${BROKER_PYTHON_MODULE_DIR}"
                  VERBATIM)

# Whenever we build the bindings, we also ensure that we stage the current
# scripts along with it.
add_dependencies(_broker python-scripts-stage)

# Set includes.
target_include_directories(_broker PUBLIC
                           ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/pybind11/include/
                           ${PYTHON_INCLUDE_DIRS})

# Set libraries to link against.
target_compile_options(_broker PRIVATE "-fvisibility=hidden")
if (ENABLE_SHARED)
  set(libbroker broker)
else ()
  set(libbroker broker_static)
endif ()
target_link_libraries(_broker PUBLIC ${libbroker} ${PYTHON_LIBRARIES})
if (ROCKSDB_FOUND)
  target_link_libraries(_broker PUBLIC ${ROCKSDB_LIBRARIES})
endif ()
if (APPLE)
  # Support multiple Python installations.
  target_link_libraries(_broker PRIVATE "-undefined dynamic_lookup")
endif ()

# Check for Link Time Optimization support (GCC/Clang)
include(CheckCXXCompilerFlag)
if (NOT CMAKE_BUILD_TYPE MATCHES DEBUG)
  check_cxx_compiler_flag("-flto" HAS_LTO_FLAG)
  if (HAS_LTO_FLAG)
    target_compile_options(_broker PRIVATE -flto)
  endif()
endif ()

# Strip unnecessary sections of the binary on Linux/Mac OS.
if (CMAKE_STRIP)
  if(APPLE)
    add_custom_command(TARGET _broker POST_BUILD
                       COMMAND ${CMAKE_STRIP} -u -r $<TARGET_FILE:_broker>)
  else()
    add_custom_command(TARGET _broker POST_BUILD
                       COMMAND ${CMAKE_STRIP} $<TARGET_FILE:_broker>)
  endif()
endif ()

if ( NOT PY_MOD_INSTALL_DIR )
  # Figure out Python module install directory.
  if (BROKER_PYTHON_PREFIX)
    set(pyver ${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR})
    set(PY_MOD_INSTALL_DIR
        ${BROKER_PYTHON_PREFIX}/lib/python${pyver}/site-packages)
  elseif (BROKER_PYTHON_HOME)
    set(PY_MOD_INSTALL_DIR ${BROKER_PYTHON_HOME}/lib/python)
  else ()
    execute_process(COMMAND ${PYTHON_EXECUTABLE} -c
      "from distutils.sysconfig import get_python_lib; print(get_python_lib())"
      OUTPUT_VARIABLE python_site_packages
      OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(PY_MOD_INSTALL_DIR ${python_site_packages})
  endif ()
endif ()
message(STATUS "Python bindings will be built and installed to:")
message(STATUS "  ${PY_MOD_INSTALL_DIR}")

install(TARGETS _broker DESTINATION ${PY_MOD_INSTALL_DIR}/broker)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/broker
        DESTINATION ${PY_MOD_INSTALL_DIR}
        REGEX "/\\..*" EXCLUDE)
