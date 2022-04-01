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

project(SMHasher3 CXX)

set(CMAKE_CXX_STANDARD 11)
set(CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

########################################
# Compiler flags (optimization, debug, etc.)
########################################

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE
      "Release"
      CACHE STRING "Choose the type of build, options are: Debug Release
  RelWithDebInfo MinSizeRel Asan." FORCE)
endif(NOT CMAKE_BUILD_TYPE)
set(CMAKE_CXX_FLAGS_DEBUG "-DDEBUG")
set(CMAKE_CXX_FLAGS_RELEASE "-DNDEBUG")

set(CMAKE_CXX_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1 -DHAVE_ASAN"
    CACHE STRING
          "Flags used by the C++ compiler during AddressSanitizer builds."
          FORCE)

if((CMAKE_MAJOR_VERSION EQUAL 3 AND CMAKE_MINOR_VERSION GREATER_EQUAL 9)
   AND (CMAKE_BUILD_TYPE STREQUAL "Release"))
  cmake_policy(SET CMP0069 NEW)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT ipo_supported OUTPUT error)
endif()

if(MSVC)
  # using Visual Studio C++, already the default with VS17
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /arch:SSE2")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /arch:SSE2")
else()
  set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
  set(CMAKE_CXX_FLAGS_DEBUG "-g -DDEBUG")
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
      set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")
    endif()
  endif()
endif()

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
  set(PROCESSOR_FAMILY "Intel")
elseif ((CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
    OR (CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64"))
  set(PROCESSOR_FAMILY "Arm")
endif()

########################################
# Size detection things
########################################

include(CheckTypeSize)
include(CheckCXXCompilerFlag)
include(CheckIncludeFileCXX)
set(CMAKE_REQUIRED_QUIET true)

check_type_size(__int64 __INT64)
check_type_size(int64_t INT64_T)

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  add_definitions(-DHAVE_BIT32)
endif()
if(HAVE_INT64_T)
  add_definitions(-DHAVE_INT64)
elseif(HAVE__INT64)
  add_definitions(-DHAVE_INT64)
endif()

check_type_size(__int128 __INT128)
if(HAVE___INT128)
  add_definitions(-DHAVE_INT128)
  message(STATUS "128-bit integers available")
endif()

########################################
# Platform detection things
########################################

if(PROCESSOR_FAMILY STREQUAL "Arm")
  add_definitions(-DHAVE_NEON)
  check_include_file_cxx("arm_neon.h" RESULT_VAR)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_ARM_NEON)
    message(STATUS "ARM NEON available")
  endif()
  check_include_file_cxx("arm_acle.h" RESULT_VAR)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_ARM_ACLE)
    message(STATUS "ARM ACLE available")
  endif()
endif()

set(DETECTSRCDIR ${CMAKE_SOURCE_DIR}/hashes/detect)

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_sse2.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_SSE_2)
  message(STATUS "x86_64 SSE 2 intrinsics available")
endif()

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_ssse3.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_SSSE3)
  message(STATUS "x86_64 SSSE3 intrinsics available")
endif()

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_sse41.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_SSE_4_1)
  message(STATUS "x86_64 SSE 4.1 intrinsics available")
endif()

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_avx2.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_AVX2)
  message(STATUS "x86_64 AVX2 intrinsics available")
endif()

# Foundational
try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_avx512_f.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_AVX512_F)
  message(STATUS "x86_64 AVX512-F intrinsics available")

  # Byte and Word
  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_avx512_bw.cpp)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_AVX512_BW)
    message(STATUS "x86_64 AVX512-BW intrinsics available")
  endif()
endif()

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_xop.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_XOP)
  message(STATUS "x86_64 XOP intrinsics available")
endif()

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_crc.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_CRC32C_X86_64)
  message(STATUS "x86_64 CRC-32C intrinsics available")
  if (MSVC AND (CMAKE_SIZEOF_VOID_P EQUAL 4) AND (MSVC_VERSION LESS 1928))
    add_definitions(-DHAVE_BROKEN_MSVC_CRC32C_HW)
    message(WARNING "MSVC version too old; CRC-32C intrinsics broken")
  endif()
endif()

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_aes.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_AES_X86_64)
  message(STATUS "x86_64 AES intrinsics available")
endif()

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_sha1.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_SHA1_X86_64)
  message(STATUS "x86_64 SHA-1 intrinsics available")
endif()

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_sha2.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_SHA2_X86_64)
  message(STATUS "x86_64 SHA-2 intrinsics available")
endif()

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_clmul.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_CLMUL_X86_64)
  message(STATUS "x86_64 CLMUL intrinsics available")
endif()

if(MSVC)
  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_umulh.cpp)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_UMULH)
    message(STATUS "x86_64 MSVC high 128-bit multiply intrinsic available")
  endif()

  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_umul128.cpp)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_UMUL128)
    message(STATUS "x86_64 MSVC full 128-bit multiply intrinsic available")
  endif()
else()
  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/x86_64_asm.cpp)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_X64_ASM)
    message(STATUS "x86_64 __asm__() available")
  endif()
endif()

try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/arm_neon_sha1.cpp)
if(RESULT_VAR)
  add_definitions(-DNEW_HAVE_SHA1_ARM)
  message(STATUS "ARM SHA-1 intrinsics available")
endif()

if(NOT MSVC)
  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/arm_aes.cpp)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_AES_ARM)
    message(STATUS "ARM AES intrinsics available")
  endif()

  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/arm_asm.cpp)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_ARM_ASM)
    message(STATUS "ARM 32-bit __asm__() available")
  endif()

  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/arm_asm64.cpp)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_ARM64_ASM)
    message(STATUS "ARM 64-bit __asm__() available")
  endif()

  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/ppc_vsx.cpp)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_PPC_VSX)
    message(STATUS "PPC VSX intrinsics available")
  endif()

  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/ppc_aes.cpp)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_AES_PPC)
    message(STATUS "PPC AES intrinsics available")
  endif()

  try_compile(RESULT_VAR ${CMAKE_BINARY_DIR} ${DETECTSRCDIR}/ppc_asm.cpp)
  if(RESULT_VAR)
    add_definitions(-DNEW_HAVE_PPC_ASM)
    message(STATUS "PPC __asm__() available")
  endif()
endif()

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

########################################
# Specific source file requirements :-/
########################################

if(NOT MSVC)
  set_source_files_properties(hashes/halftimehash.cpp PROPERTIES COMPILE_FLAGS "-flax-vector-conversions -Wno-ignored-attributes")
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
  hashes/lib/AES.cpp
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
  util/Bitvec.cpp
  util/Platform.cpp
  util/Analyze.cpp
  util/Stats.cpp
  util/Types.cpp
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
target_include_directories(SMHasher3 PRIVATE hashes tests util)
target_link_libraries(SMHasher3 SMHasher3Tests SMHasher3Hashlib
                      ${THREAD_LIBS_PREFIX} ${CMAKE_THREAD_LIBS_INIT} ${THREAD_LIBS_SUFFIX})

if(ipo_supported)
#  message(STATUS "IPO / LTO enabled")
#  set_property(TARGET SMHasher3Tests PROPERTY INTERPROCEDURAL_OPTIMIZATION True)
#  set_property(TARGET SMHasher3      PROPERTY INTERPROCEDURAL_OPTIMIZATION True)
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
