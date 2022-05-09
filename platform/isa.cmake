########################################
# Instruction set availability detection
########################################

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

# Map of feature variable to the file that detects it.
# Cmake doesn't have associative arrays, so just do this instead.
set(detectVarsFilesMap
  FEATURE_SSE2_FOUND       x86_64_sse2.cpp
  FEATURE_SSSE3_FOUND      x86_64_ssse3.cpp
  FEATURE_SSE41_FOUND      x86_64_sse41.cpp
  FEATURE_XOP_FOUND        x86_64_xop.cpp
  FEATURE_X64CRC_FOUND     x86_64_crc.cpp
  FEATURE_X64CLMUL_FOUND   x86_64_clmul.cpp
  FEATURE_AESNI_FOUND      x86_64_aes.cpp
  FEATURE_X64SHA1_FOUND    x86_64_sha1.cpp
  FEATURE_X64SHA2_FOUND    x86_64_sha2.cpp
  FEATURE_AVX2_FOUND       x86_64_avx2.cpp
  FEATURE_AVX512F_FOUND    x86_64_avx512_f.cpp
  FEATURE_AVX512BW_FOUND   x86_64_avx512_bw.cpp
  FEATURE_UMULH_FOUND      x86_64_umulh.cpp
  FEATURE_UMUL128_FOUND    x86_64_umul128.cpp
  FEATURE_X64ASM_FOUND     x86_64_asm.cpp
  FEATURE_ARMAES_FOUND     arm_aes.cpp
  FEATURE_ARMSHA1_FOUND    arm_neon_sha1.cpp
  FEATURE_ARMASM32_FOUND   arm_asm.cpp
  FEATURE_ARMASM64_FOUND   arm_asm64.cpp
  FEATURE_PPCVSX_FOUND     ppc_vsx.cpp
  FEATURE_PPCAES_FOUND     ppc_aes.cpp
  FEATURE_PPCASM_FOUND     ppc_asm.cpp
)

# Lookup feature var in the map
function(lookupDetectFile var feature)
  list(FIND detectVarsFilesMap ${feature} index)
  if (index EQUAL -1)
    message(FATAL_ERROR "Cannot find ${feature} in detectVarsFilesMap; skipping detection")
    set(${var} OFF)
  else()
    math(EXPR index "${index} + 1")
    list(GET detectVarsFilesMap ${index} filename)
    set(${var} ${filename} PARENT_SCOPE)
  endif()
endfunction()

# Compute the list detection source files plus their hashes
set(isFile OFF)
foreach(entry ${detectVarsFilesMap})
  if(isFile)
    file(SHA256 ${DETECT_DIR}/${entry} filehash)
    list(APPEND detectFiles ${DETECT_DIR}/${entry})
    list(APPEND detectFileHashes ${filehash})
    set(isFile OFF)
  else()
    set(isFile ON)
  endif()
endforeach()
# Stringify hash list
set(detectFileHashes "${detectFileHashes}")

# Mark cmake configuration as depending on detection files
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${detectFiles})

# Unset all the feature detection variables if any of their hashes
# changed, since there's apparently NO OTHER WAY of clearing these
# cached variables iff the files post-date the CMake cache... :-{
if((DEFINED LAST_DETECT_HASH) AND (LAST_DETECT_HASH STREQUAL detectFileHashes))
  message(STATUS "Using cached instruction-set detection")
else()
  message(STATUS "Clearing instruction-set detection cache, reprobing")
  set(isFile OFF)
  foreach(entry ${detectVarsFilesMap})
    if(isFile)
      set(isFile OFF)
    else()
      unset(${entry} CACHE)
      unset(${entry})
      set(isFile ON)
    endif()
  endforeach()
  set(LAST_DETECT_HASH ${detectFileHashes} CACHE STRING "Internal use only" FORCE)
endif()  

# Function for detection of features via try_compile(), with caching
# of results
function(feature_detect var)
  if (NOT DEFINED ${var})
    lookupDetectFile(file ${var})
    try_compile(${var} ${CMAKE_BINARY_DIR} ${DETECT_DIR}/${file})
  endif()
endfunction()

########################################

feature_detect(FEATURE_SSE2_FOUND)
if(FEATURE_SSE2_FOUND)
  add_definitions(-DNEW_HAVE_SSE_2)
  message(STATUS "  x86_64 SSE 2 intrinsics available")

  feature_detect(FEATURE_SSSE3_FOUND)
  if(FEATURE_SSSE3_FOUND)
    add_definitions(-DNEW_HAVE_SSSE3)
    message(STATUS "  x86_64 SSSE3 intrinsics available")

    feature_detect(FEATURE_SSE41_FOUND)
    if(FEATURE_SSE41_FOUND)
      add_definitions(-DNEW_HAVE_SSE_4_1)
      message(STATUS "  x86_64 SSE 4.1 intrinsics available")

      feature_detect(FEATURE_XOP_FOUND)
      if(FEATURE_XOP_FOUND)
	add_definitions(-DNEW_HAVE_XOP)
	message(STATUS "  x86_64 XOP intrinsics available")
      endif()

      feature_detect(FEATURE_X64CRC_FOUND)
      if(FEATURE_X64CRC_FOUND)
	add_definitions(-DNEW_HAVE_CRC32C_X86_64)
	message(STATUS "  x86_64 CRC-32C intrinsics available")
	if (MSVC AND (CMAKE_SIZEOF_VOID_P EQUAL 4) AND (MSVC_VERSION LESS 1928))
	  add_definitions(-DHAVE_BROKEN_MSVC_CRC32C_HW)
	  message(WARNING "MSVC version too old; CRC-32C intrinsics broken")
	endif()
      endif()

      feature_detect(FEATURE_X64CLMUL_FOUND)
      if(FEATURE_X64CLMUL_FOUND)
	add_definitions(-DNEW_HAVE_CLMUL_X86_64)
	message(STATUS "  x86_64 CLMUL intrinsics available")
      endif()

      feature_detect(FEATURE_AESNI_FOUND)
      if(FEATURE_AESNI_FOUND)
	add_definitions(-DNEW_HAVE_AES_X86_64)
	message(STATUS "  x86_64 AES intrinsics available")
      endif()

      feature_detect(FEATURE_X64SHA1_FOUND)
      if(FEATURE_X64SHA1_FOUND)
	add_definitions(-DNEW_HAVE_SHA1_X86_64)
	message(STATUS "  x86_64 SHA-1 intrinsics available")
      endif()

      feature_detect(FEATURE_X64SHA2_FOUND)
      if(FEATURE_X64SHA2_FOUND)
	add_definitions(-DNEW_HAVE_SHA2_X86_64)
	message(STATUS "  x86_64 SHA-2 intrinsics available")
      endif()

      feature_detect(FEATURE_AVX2_FOUND)
      if(FEATURE_AVX2_FOUND)
	add_definitions(-DNEW_HAVE_AVX2)
	message(STATUS "  x86_64 AVX2 intrinsics available")

	# Foundational
	feature_detect(FEATURE_AVX512F_FOUND)
	if(FEATURE_AVX512F_FOUND)
	  add_definitions(-DNEW_HAVE_AVX512_F)
	  message(STATUS "  x86_64 AVX512-F intrinsics available")

	  # Byte and Word
	  feature_detect(FEATURE_AVX512BW_FOUND)
	  if(FEATURE_AVX512BW_FOUND)
	    add_definitions(-DNEW_HAVE_AVX512_BW)
	    message(STATUS "  x86_64 AVX512-BW intrinsics available")
	  endif()
	endif()
      endif()
    endif()
  endif()
endif()

if(MSVC)
  feature_detect(FEATURE_UMULH_FOUND)
  if(FEATURE_UMULH_FOUND)
    add_definitions(-DNEW_HAVE_UMULH)
    message(STATUS "  x86_64 MSVC high 128-bit multiply intrinsic available")
  endif()

  feature_detect(FEATURE_UMUL128_FOUND)
  if(FEATURE_UMUL128_FOUND)
    add_definitions(-DNEW_HAVE_UMUL128)
    message(STATUS "  x86_64 MSVC full 128-bit multiply intrinsic available")
  endif()
else()
  feature_detect(FEATURE_X64ASM_FOUND)
  if(FEATURE_X64ASM_FOUND)
    add_definitions(-DNEW_HAVE_X64_ASM)
    message(STATUS "  x86_64 __asm__() available")
  endif()

  feature_detect(FEATURE_ARMAES_FOUND)
  if(FEATURE_ARMAES_FOUND)
    add_definitions(-DNEW_HAVE_AES_ARM)
    message(STATUS "  ARM AES intrinsics available")
  endif()

  feature_detect(FEATURE_ARMSHA1_FOUND)
  if(FEATURE_ARMSHA1_FOUND)
    add_definitions(-DNEW_HAVE_SHA1_ARM)
    message(STATUS "  ARM SHA-1 intrinsics available")
  endif()

  feature_detect(FEATURE_ARMASM32_FOUND)
  if(FEATURE_ARMASM32_FOUND)
    add_definitions(-DNEW_HAVE_ARM_ASM)
    message(STATUS "  ARM 32-bit __asm__() available")
  endif()

  feature_detect(FEATURE_ARMASM64_FOUND)
  if(FEATURE_ARMASM64_FOUND)
    add_definitions(-DNEW_HAVE_ARM64_ASM)
    message(STATUS "  ARM 64-bit __asm__() available")
  endif()

  feature_detect(FEATURE_PPCVSX_FOUND)
  if(FEATURE_PPCVSX_FOUND)
    add_definitions(-DNEW_HAVE_PPC_VSX)
    message(STATUS "  PPC VSX intrinsics available")
  endif()

  feature_detect(FEATURE_PPCAES_FOUND)
  if(FEATURE_PPCAES_FOUND)
    add_definitions(-DNEW_HAVE_AES_PPC)
    message(STATUS "  PPC AES intrinsics available")
  endif()

  feature_detect(FEATURE_PPCASM_FOUND)
  if(FEATURE_PPCASM_FOUND)
    add_definitions(-DNEW_HAVE_PPC_ASM)
    message(STATUS "  PPC __asm__() available")
  endif()
endif()
