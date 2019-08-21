cmake_minimum_required(VERSION 3.14)

function(zeekComponents)
  add_subdirectory("zeekutils")
  add_subdirectory("zeekdatabase")
  add_subdirectory("zeekaudisp")
endfunction()

zeekComponents()
