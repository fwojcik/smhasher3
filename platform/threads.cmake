########################################
# Threading availability detection
########################################

find_package( Threads )
if(NOT (MSVC))
  if(NOT ("${CMAKE_THREAD_LIBS_INIT}" STREQUAL ""))
    # Some Linux installations need the threading library linked
    # in as "whole-archive", or required symbols get missed,
    # leading to link failures. This shouldn't hurt to add if it
    # is not required on this system.
    whole_archive_link_flags("${CMAKE_THREAD_LIBS_INIT}" threads_link_command)
  endif()
endif()
if(Threads_FOUND)
  add_definitions(-DHAVE_THREADS)
endif()
