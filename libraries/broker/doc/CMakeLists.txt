if (NOT TARGET doc)
  add_custom_target(doc)
endif ()

set(html_output_dir ${CMAKE_CURRENT_BINARY_DIR}/html)

add_custom_target(broker-doc-html
  COMMAND sphinx-build
          -b html
          -c ${CMAKE_CURRENT_SOURCE_DIR}
          ${CMAKE_CURRENT_SOURCE_DIR}
          ${html_output_dir}
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  COMMENT "[Sphinx] Generate Broker HTML documentation in ${html_output_dir}")

add_dependencies(doc broker-doc-html)

add_subdirectory(_examples)
