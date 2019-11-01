#
# This compiles the examples in this directory. They won't really work,
# and we don't execute them, but we want to make sure that they are
# syntactially correct at least.
#

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Setup correct broker library (static/shared).
if (ENABLE_SHARED)
  set(libbroker broker)
else ()
  set(libbroker broker_static)
endif ()

macro(make_example cc)
    add_executable(${cc} ${cc}.cc)
    target_link_libraries(${cc} ${libbroker})
    add_dependencies(doc ${cc})
endmacro()

make_example(synopsis)
make_example(comm)
make_example(stores)
make_example(ping)

