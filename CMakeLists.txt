cmake_minimum_required(VERSION 3.2)
cmake_policy(SET CMP0003 NEW)

project(SMHasher3 C CXX)

include(CheckCCompilerFlag)
# Check if the same compile family is used for both C and CXX
if(NOT (CMAKE_C_COMPILER_ID STREQUAL CMAKE_CXX_COMPILER_ID))
  message(WARNING "CMAKE_C_COMPILER_ID (${CMAKE_C_COMPILER_ID}) is different "
                  "from CMAKE_CXX_COMPILER_ID (${CMAKE_CXX_COMPILER_ID}). "
                  "The final binary may be unusable.")
endif()

add_subdirectory(hashes)

set(CMAKE_CXX_STANDARD 11)
set(CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      "Release"
      CACHE STRING "Choose the type of build, options are: Debug Release
  RelWithDebInfo MinSizeRel Asan." FORCE)
endif(NOT CMAKE_BUILD_TYPE)
set(CMAKE_C_FLAGS_DEBUG "-DDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "-DDEBUG")
set(CMAKE_C_FLAGS_RELEASE "-DNDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG")

# AddressSanitize
set(CMAKE_C_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1 -DHAVE_ASAN"
    CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
          FORCE)
set(CMAKE_CXX_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1 -DHAVE_ASAN"
    CACHE STRING
          "Flags used by the C++ compiler during AddressSanitizer builds."
          FORCE)

if(MSVC)
  # using Visual Studio C++, already the default with VS17
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:SSE2")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:SSE2")
else()
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
  set(CMAKE_C_FLAGS_DEBUG "-g -DDEBUG")
  set(CMAKE_CXX_FLAGS_DEBUG "-g -DDEBUG")
  set(CMAKE_C_FLAGS_RELEASE "-O3 -DNDEBUG -ggdb3")
  set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -ggdb3")
  if(CMAKE_COMPILER_IS_GNUCC
     OR (CMAKE_C_COMPILER_ID STREQUAL AppleClang)
     OR (CMAKE_C_COMPILER_ID STREQUAL Clang)
     OR (CMAKE_C_COMPILER_ID STREQUAL Intel))
    set(CMAKE_CXX_FLAGS_DEBUG
        "${CMAKE_CXX_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address,undefined -DHAVE_ASAN -DHAVE_UBSAN"
    )
    set(CMAKE_LINKER_FLAGS_DEBUG
        "${CMAKE_LINKER_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address,undefined"
    )
    if(NOT CMAKE_CROSSCOMPILING)
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
    endif()
  endif()
endif()

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -I${CMAKE_SOURCE_DIR}/util")
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I${CMAKE_SOURCE_DIR}/util")

find_package( Threads )
if(NOT (MSVC))
  if(NOT ("${CMAKE_THREAD_LIBS_INIT}" STREQUAL ""))
    set(THREAD_LIBS_PREFIX "-Wl,--whole-archive")
    set(THREAD_LIBS_SUFFIX "-Wl,--no-whole-archive")
  endif()
endif()
if(Threads_FOUND)
  add_definitions(-DHAVE_THREADS)
endif()

if((CMAKE_MAJOR_VERSION EQUAL 3 AND CMAKE_MINOR_VERSION GREATER_EQUAL 9)
   AND (CMAKE_BUILD_TYPE STREQUAL "Release"))
  cmake_policy(SET CMP0069 NEW)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported OUTPUT error)
endif()

add_library(
  SMHasher3Tests STATIC
#
  util/Bitvec.cpp
  util/Platform.cpp
  util/Analyze.cpp
  util/Stats.cpp
  util/Types.cpp
#
  tests/SanityTest.cpp
  tests/AvalancheTest.cpp
  tests/BitIndependenceTest.cpp
  tests/DifferentialTest.cpp
  tests/DiffDistributionTest.cpp
  tests/HashMapTest.cpp
  tests/SparseKeysetTest.cpp
  tests/ZeroesKeysetTest.cpp
  tests/WindowedKeysetTest.cpp
  tests/CyclicKeysetTest.cpp
  tests/TwoBytesKeysetTest.cpp
  tests/TextKeysetTest.cpp
  tests/PermutationKeysetTest.cpp
  tests/SeedTest.cpp
  tests/BadSeedsTest.cpp
  tests/PerlinNoiseTest.cpp
  tests/PopcountTest.cpp
  tests/PRNGTest.cpp
  tests/SpeedTest.cpp
)

add_executable(SMHasher3 main.cpp)
set_source_files_properties(main.cpp PROPERTIES COMPILE_FLAGS "-I${CMAKE_SOURCE_DIR}/hashes -I${CMAKE_SOURCE_DIR}/tests")

if(ipo_supported)
#  message(STATUS "IPO / LTO enabled")
#  set_property(TARGET SMHasher3Tests PROPERTY INTERPROCEDURAL_OPTIMIZATION True)
#  set_property(TARGET SMHasher3      PROPERTY INTERPROCEDURAL_OPTIMIZATION True)
else()
  message(STATUS "IPO / LTO not supported: <${error}>")
endif()

target_link_libraries(SMHasher3 SMHasher3Tests SMHasher3Hashes SMHasher3Hashlib
                      ${THREAD_LIBS_PREFIX} ${CMAKE_THREAD_LIBS_INIT} ${THREAD_LIBS_SUFFIX})

if(NOT (CMAKE_CROSSCOMPILING))
  enable_testing()
  add_test(VerifyAll SMHasher3 --test=VerifyAll)
  add_test(Sanity SMHasher3 --test=Sanity)
  add_test(Speed SMHasher3 --test=Speed)
  add_test(Cyclic SMHasher3 --test=Cyclic)
  add_test(Zeroes SMHasher3 --test=Zeroes)
endif()

if(MSVC)
add_custom_target(
  TAGS
  COMMAND dir /b /s *.cpp *.cc *.h | etags --language=c++ -
  DEPENDS ${SRCS}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
else()
add_custom_target(
  TAGS
  COMMAND find . -name *.cpp -or -name *.cc -or -name *.h -print | etags --language=c++ -
  DEPENDS ${SRCS}
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()
