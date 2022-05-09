########################################
# General system detection
########################################

message(STATUS "CMAKE_SYSTEM_PROCESSOR: ${CMAKE_SYSTEM_PROCESSOR}")

if ((CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "i386")
    OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "i586")
    OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "i686")
    OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "amd64") # freebsd
    OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "AMD64") # windows
    OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "x86"))
  set(PROCESSOR_FAMILY "x86")
elseif ((CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64"))
  set(PROCESSOR_FAMILY "Arm")
else ()
  set(PROCESSOR_FAMILY "Other")
endif()

if(MSVC)
  message(STATUS "MSVC detected")
  set(MSVC_IMPL
    "#include <stdlib.h>\n"
  )
else()
  set(MSVC_IMPL "")
endif()
