cmake_minimum_required(VERSION 3.2)
cmake_policy(SET CMP0003 NEW)
if(POLICY CMP0056) # Honor link flags in try_compile() source-file signature.
  cmake_policy(SET CMP0056 NEW) # since 3.2
endif()
if(POLICY CMP0065)
  cmake_policy(SET CMP0065 NEW) # since 3.4. ENABLE_EXPORTS.
endif()
if(POLICY CMP0066) # honor per-config flags in try_compile() source-file
                   # signature.
  cmake_policy(SET CMP0066 NEW) # since 3.7
endif()
if(POLICY CMP0069) # Honor IPO setting for all supported compilers, not just icc
  cmake_policy(SET CMP0069 NEW) # since 3.9
endif()

set(CMAKE_CXX_STANDARD 11)
set(CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# "C" needs to be enabled for some builtin CMake tests :-/
project(SMHasher3 C CXX)

include(CheckCCompilerFlag)
# Check if the same compile family is used for both C and CXX
if(NOT (CMAKE_C_COMPILER_ID STREQUAL CMAKE_CXX_COMPILER_ID))
  message(WARNING "CMAKE_C_COMPILER_ID (${CMAKE_C_COMPILER_ID}) is different "
    "from CMAKE_CXX_COMPILER_ID (${CMAKE_CXX_COMPILER_ID}). "
    "The final binary may be unusable.")
endif()

########################################
# Compiler flags (optimization, debug, etc.)
########################################

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      "Release"
      CACHE STRING "Choose the type of build, options are: Release Debug Asan" FORCE)
endif(NOT CMAKE_BUILD_TYPE)

set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -g")
set(CMAKE_CXX_FLAGS_DEBUG   "-O1 -DDEBUG  -g")
set(CMAKE_CXX_FLAGS_ASAN    "${CMAKE_CXX_FLAGS_DEBUG}")

if(MSVC)
  # using Visual Studio C++, already the default with VS17
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:SSE2")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL GNU
     OR (CMAKE_CXX_COMPILER_ID STREQUAL AppleClang)
     OR (CMAKE_CXX_COMPILER_ID STREQUAL Clang)
     OR (CMAKE_CXX_COMPILER_ID STREQUAL Intel))

  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE}  -ggdb3")
  set(CMAKE_CXX_FLAGS_DEBUG   "${CMAKE_CXX_FLAGS_DEBUG}    -ggdb3")
  set(CMAKE_CXX_FLAGS_ASAN    "${CMAKE_CXX_FLAGS_ASAN} -Og -ggdb3  \
      -fsanitize=address,undefined -fno-optimize-sibling-calls \
      -fsanitize-address-use-after-scope -fno-omit-frame-pointer")

  if(NOT CMAKE_CROSSCOMPILING)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
  endif()

  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
endif()

function(whole_archive_link_flags lib var)
  if(MSVC)
    set(${var} -WHOLEARCHIVE:$<TARGET_FILE:${lib}> PARENT_SCOPE)
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(${var} -Wl,-force_load,$<TARGET_FILE:${lib}> PARENT_SCOPE)
  else()
    set(${var} -Wl,--whole-archive ${lib} -Wl,--no-whole-archive PARENT_SCOPE)
  endif()
endfunction()

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

########################################
# Endianness and size detection things
########################################

include(CheckTypeSize)
set(CMAKE_REQUIRED_QUIET true)

option(ENDIAN_DETECT_BUILDTIME "Try to detect system endianness at build time" ON)
if (ENDIAN_DETECT_BUILDTIME AND (NOT DEFINED DETECTED_LITTLE_ENDIAN))
  # Can't use include (TestBigEndian) because it does things
  # we don't want, like sometimes guess endianness based on
  # machine running cmake and causing fatal errors.
  # So we include the relevant bits here.
  #message(DEBUG "Checking target endianness")

  CHECK_TYPE_SIZE("unsigned short" CMAKE_SIZEOF_UNSIGNED_SHORT)
  if(CMAKE_SIZEOF_UNSIGNED_SHORT EQUAL 2)
    set(CMAKE_16BIT_TYPE "unsigned short")
  else()
    CHECK_TYPE_SIZE("unsigned int"   CMAKE_SIZEOF_UNSIGNED_INT)
    if(CMAKE_SIZEOF_UNSIGNED_INT EQUAL 2)
      set(CMAKE_16BIT_TYPE "unsigned int")
    else()
      CHECK_TYPE_SIZE("unsigned long"  CMAKE_SIZEOF_UNSIGNED_LONG)
      if(CMAKE_SIZEOF_UNSIGNED_LONG EQUAL 2)
        set(CMAKE_16BIT_TYPE "unsigned long")
      endif()
    endif()
  endif()

  if(DEFINED CMAKE_16BIT_TYPE)
    #message(DEBUG "Using ${CMAKE_16BIT_TYPE}")

    configure_file(
      "${CMAKE_ROOT}/Modules/TestEndianess.c.in"
      "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/TestEndianess.c"
      @ONLY)

    file(READ "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/TestEndianess.c" TEST_ENDIANESS_FILE_CONTENT)

    if(NOT DEFINED RESULT_ENDIAN_COMPILE)
      try_compile(RESULT_ENDIAN_COMPILE "${CMAKE_BINARY_DIR}"
	"${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeTmp/TestEndianess.c"
	OUTPUT_VARIABLE OUTPUT
	COPY_FILE "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/TestEndianess.bin")
    endif()

    if(RESULT_ENDIAN_COMPILE)
      file(STRINGS
        "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/TestEndianess.bin"
	CMAKE_TEST_ENDIANESS_STRINGS_LE
	LIMIT_COUNT 1
	REGEX "THIS IS LITTLE ENDIAN")
      file(STRINGS
        "${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/TestEndianess.bin"
	CMAKE_TEST_ENDIANESS_STRINGS_BE
	LIMIT_COUNT 1
	REGEX "THIS IS BIG ENDIAN")
    endif()
  endif()

  if((DEFINED CMAKE_TEST_ENDIANESS_STRINGS_LE) AND (DEFINED CMAKE_TEST_ENDIANESS_STRINGS_BE))
    if(NOT (CMAKE_TEST_ENDIANESS_STRINGS_BE  AND  CMAKE_TEST_ENDIANESS_STRINGS_LE))
      if(CMAKE_TEST_ENDIANESS_STRINGS_LE)
        set(DETECTED_LITTLE_ENDIAN ON CACHE BOOL "Result of build time endian test" FORCE)
      endif()
      if(CMAKE_TEST_ENDIANESS_STRINGS_BE)
        set(DETECTED_LITTLE_ENDIAN OFF CACHE BOOL "Result of build time endian test" FORCE)
      endif()
    endif()
  endif()
endif()

if (ENDIAN_DETECT_BUILDTIME)
  if(DEFINED DETECTED_LITTLE_ENDIAN)
    if(DETECTED_LITTLE_ENDIAN)
      message(STATUS "Setting target as little-endian")
      add_definitions(-DFORCE_LITTLE_ENDIAN)
    else()
      message(STATUS "Setting target as big-endian")
      add_definitions(-DFORCE_BIG_ENDIAN)
    endif()
  else()
    message(WARNING "Cannot detect target endianness; falling back to runtime detection")
  endif()
else()
  message(STATUS "Using runtime endianness detection")
endif()

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

########################################
# Platform detection things
########################################

set(DETECT_DIR ${CMAKE_SOURCE_DIR}/detect)

include(${DETECT_DIR}/detect.cmake)

include(CheckIncludeFileCXX)

if(PROCESSOR_FAMILY STREQUAL "Arm")
  add_definitions(-DHAVE_NEON)
  check_include_file_cxx("arm_neon.h" RESULT_NEON_INCLUDE)
  if(RESULT_NEON_INCLUDE)
    add_definitions(-DNEW_HAVE_ARM_NEON)
    message(STATUS "ARM NEON available")
  endif()
  check_include_file_cxx("arm_acle.h" RESULT_ACLE_INCLUDE)
  if(RESULT_ACLE_INCLUDE)
    add_definitions(-DNEW_HAVE_ARM_ACLE)
    message(STATUS "ARM ACLE available")
  endif()
endif()

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

########################################
# Specific source file requirements :-/
########################################

if(NOT MSVC)
  set_source_files_properties(hashes/halftimehash.cpp PROPERTIES
    COMPILE_FLAGS "-flax-vector-conversions -Wno-ignored-attributes")
  if (CMAKE_CXX_COMPILER_ID STREQUAL Intel)
    set_source_files_properties(hashes/floppsyhash.cpp PROPERTIES
      COMPILE_FLAGS "-fp-model strict")
  else()
    set_source_files_properties(hashes/floppsyhash.cpp PROPERTIES
      COMPILE_FLAGS "-ffp-contract=off")
  endif()
endif(NOT MSVC)

########################################
# Build all the hashes
########################################

add_library(
  SMHasher3Hashlib STATIC
#
  hashes/Hashlib.cpp
  hashes/Hashinfo.cpp
  hashes/Hashrefs.cpp
  hashes/lib/AEStables.cpp
#
  hashes/donothing.cpp
  hashes/badhash.cpp
  hashes/aesrng.cpp
#
#########################################
# Normal hashes are sorted biggest->smallest to try to minimize
# parallel compilation times
#########################################
#
  hashes/pmp_multilinear.cpp
  hashes/xxhash.cpp
  hashes/t1ha.cpp
  hashes/farmhash.cpp
  hashes/halftimehash.cpp
  hashes/blake2.cpp
  hashes/blake3.cpp
  hashes/umash.cpp
  hashes/mum_mir.cpp
  hashes/cityhash.cpp
  hashes/nmhash.cpp
  hashes/ascon.cpp
  hashes/rmd.cpp
  hashes/beamsplitter.cpp
  hashes/sha2.cpp
  hashes/sha1.cpp
  hashes/pearson.cpp
  hashes/vmac.cpp
  hashes/clhash.cpp
  hashes/spookyhash.cpp
  hashes/meowhash.cpp
  hashes/metrohash.cpp
  hashes/farsh.cpp
  hashes/siphash.cpp
  hashes/crc.cpp
  hashes/chaskey.cpp
  hashes/tabulation.cpp
  hashes/komihash.cpp
  hashes/multiply_shift.cpp
  hashes/md5.cpp
  hashes/fnv.cpp
  hashes/hasshe2.cpp
  hashes/prvhash.cpp
  hashes/murmurhash3.cpp
  hashes/aesrng.cpp
  hashes/wyhash.cpp
  hashes/discohash.cpp
  hashes/sha3.cpp
  hashes/poly_mersenne.cpp
  hashes/murmurhash2.cpp
  hashes/falkhash.cpp
  hashes/fletcher.cpp
  hashes/crap.cpp
  hashes/blockpearson.cpp
  hashes/perlhashes.cpp
  hashes/jodyhash.cpp
  hashes/khash.cpp
  hashes/floppsyhash.cpp
  hashes/seahash.cpp
  hashes/falcon_oaat.cpp
  hashes/lookup3.cpp
  hashes/donothing.cpp
  hashes/badhash.cpp
  hashes/fasthash.cpp
  hashes/aesnihash.cpp
  hashes/o1hash.cpp
  hashes/pengyhash.cpp
  hashes/mx3.cpp
  hashes/superfasthash.cpp
  hashes/murmurhash1.cpp
  hashes/murmur_oaat.cpp
  hashes/x17.cpp
)
target_include_directories(SMHasher3Hashlib PRIVATE util)

add_library(
  SMHasher3Tests STATIC
#
  util/Platform.cpp
  util/Analyze.cpp
  util/Blob.cpp
  util/Stats.cpp
  util/VCode.cpp
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
target_include_directories(SMHasher3Tests PRIVATE util)

add_executable(SMHasher3 main.cpp)
target_include_directories(SMHasher3 PRIVATE hashes tests util ${CMAKE_BINARY_DIR}/include)
target_link_libraries(SMHasher3 SMHasher3Tests SMHasher3Hashlib ${threads_link_command})

########################################
# Miscellany
########################################

find_package(Git)
add_custom_target(SMHasher3Version ${CMAKE_COMMAND}
    -D SRC=${CMAKE_SOURCE_DIR}/version.h.in
    -D DST=${CMAKE_BINARY_DIR}/include/version.h
    -D GIT_EXECUTABLE=${GIT_EXECUTABLE}
    -P ${CMAKE_SOURCE_DIR}/version.cmake
)
add_dependencies(SMHasher3 SMHasher3Version)

if((CMAKE_MAJOR_VERSION EQUAL 3 AND CMAKE_MINOR_VERSION GREATER_EQUAL 9)
   AND (CMAKE_BUILD_TYPE STREQUAL "Release"))
  cmake_policy(SET CMP0069 NEW)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported OUTPUT error)
endif()
if(ipo_supported)
  message(STATUS "IPO / LTO enabled")
  set_property(TARGET SMHasher3Tests PROPERTY INTERPROCEDURAL_OPTIMIZATION True)
  set_property(TARGET SMHasher3      PROPERTY INTERPROCEDURAL_OPTIMIZATION True)
else()
  message(STATUS "IPO / LTO not supported: <${error}>")
endif()

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
