cmake_minimum_required(VERSION 3.14)
project("openssl")

# TODO: In order to get reproducible builds, the system OpenSSL
# library should be avoided. Everything should be compiled using
# the osquery-toolchain

function(zeekAgentLibrariesOpenSSL)
  find_package(OpenSSL REQUIRED)

  add_library(thirdparty_openssl INTERFACE)
  if(TARGET OpenSSL::SSL)
    target_link_libraries(thirdparty_openssl INTERFACE
      OpenSSL::SSL
      OpenSSL::Crypto    
    )

  else()
    target_link_libraries(thirdparty_openssl INTERFACE
      "${OPENSSL_LIBRARIES}"
    )

    target_include_directories(thirdparty_openssl INTERFACE
      "${OPENSSL_INCLUDE_DIR}"
    )
  endif()
endfunction()

zeekAgentLibrariesOpenSSL()
