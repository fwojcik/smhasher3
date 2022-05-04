########################################
# Fixed-width integer type detection
########################################

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  add_definitions(-DHAVE_32BIT_PLATFORM)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
  add_definitions(-DHAVE_64BIT_PLATFORM)
endif()

check_type_size(__int128 __INT128)
if(HAVE___INT128)
  add_definitions(-DHAVE_INT128)
  message(STATUS "128-bit integers available")
endif()

