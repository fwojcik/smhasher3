########################################
# Instruction set availability detection
########################################

### Find header files

include(CheckIncludeFileCXX)

if(PROCESSOR_FAMILY STREQUAL "Arm")
  check_include_file_cxx("arm_neon.h" RESULT_NEON_INCLUDE)
  if(RESULT_NEON_INCLUDE)
    add_definitions(-DHAVE_ARM_NEON)
    message(STATUS "ARM NEON available")
  endif()
  check_include_file_cxx("arm_acle.h" RESULT_ACLE_INCLUDE)
  if(RESULT_ACLE_INCLUDE)
    add_definitions(-DHAVE_ARM_ACLE)
    message(STATUS "ARM ACLE available")
  endif()
endif()


###  Find support for instruction set features

# Map of feature variable to the file that detects it.
# Cmake doesn't have associative arrays, so just do this instead.

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
  FEATURE_AVX_FOUND        x86_64_avx.cpp
  FEATURE_AVX2_FOUND       x86_64_avx2.cpp
  FEATURE_AVX512F_FOUND    x86_64_avx512_f.cpp
  FEATURE_AVX512BW_FOUND   x86_64_avx512_bw.cpp
  FEATURE_UMULH_FOUND      x86_64_umulh.cpp
  FEATURE_UMUL128_FOUND    x86_64_umul128.cpp
  FEATURE_X64ASM_FOUND     x86_64_asm.cpp
  FEATURE_ARMAES_FOUND     arm_aes.cpp
  FEATURE_ARMSHA1_FOUND    arm_neon_sha1.cpp
  FEATURE_ARMSHA2_FOUND    arm_neon_sha2.cpp
  FEATURE_ARMASM32_FOUND   arm_asm.cpp
  FEATURE_ARMASM64_FOUND   arm_asm64.cpp
  FEATURE_PPCVSX_FOUND     ppc_vsx.cpp
  FEATURE_PPCAES_FOUND     ppc_aes.cpp
  FEATURE_PPCASM_FOUND     ppc_asm.cpp
)

# Function for detection of features via try_compile(), with caching
# of results. try_compile() implicitly caches the result var value,
# but if any of the detection input files change, then the variables
# will be cleared via setVarsDepend() below.
function(feature_detect var)
  if (NOT DEFINED ${var})
    lookupDetectFile(file ${var})
    try_compile(${var} ${CMAKE_BINARY_DIR} ${DETECT_DIR}/${file})
  endif()
endfunction()

########################################

# Compute the list of detection source files and the list of variables
# whose caching status depends on those source files. These are two
# independent lists which merely happen to be the same length
# here. Their contents do not necessarily have to depend on each other
# for setConfigureDepends() to work. If any of the files change, then
# all of the variables are cleared, and so all of the ISA detections
# happen again. This allows complex dependencies between them to work.
#
# By depending on this .cmake file, the cache will be cleared if the
# list of files were to ever change, as this file is the only one that
# can change it.

set(isFile OFF)
unset(detectVars)
set(detectFiles "${DETECT_DIR}/isa.cmake")
foreach(entry ${detectVarsFilesMap})
  if(isFile)
    list(APPEND detectFiles "${DETECT_DIR}/${entry}")
    set(isFile OFF)
  else()
    list(APPEND detectVars "${entry}")
    set(isFile ON)
  endif()
endforeach()

checkCachedVarsDepend(DETECT "instruction-set availability")
setCachedVarsDepend(DETECT detectVars detectFiles)

########################################

feature_detect(FEATURE_SSE2_FOUND)
if(FEATURE_SSE2_FOUND)
  add_definitions(-DHAVE_SSE_2)
  message(STATUS "  x86_64 SSE 2 intrinsics available")

  feature_detect(FEATURE_SSSE3_FOUND)
  if(FEATURE_SSSE3_FOUND)
    add_definitions(-DHAVE_SSSE_3)
    message(STATUS "  x86_64 SSSE3 intrinsics available")

    feature_detect(FEATURE_SSE41_FOUND)
    if(FEATURE_SSE41_FOUND)
      add_definitions(-DHAVE_SSE_4_1)
      message(STATUS "  x86_64 SSE 4.1 intrinsics available")

      feature_detect(FEATURE_XOP_FOUND)
      if(FEATURE_XOP_FOUND)
	add_definitions(-DHAVE_XOP)
	message(STATUS "  x86_64 XOP intrinsics available")
      endif()

      feature_detect(FEATURE_X64CRC_FOUND)
      if(FEATURE_X64CRC_FOUND)
        # This allegedly falls into a MSVC CL 14.16.27023 32-bit
        # compiler bug. 14.28.29910 allegedly works fine.
        if (MSVC AND (CMAKE_SIZEOF_VOID_P EQUAL 4) AND (MSVC_VERSION LESS 1928))
	  add_definitions(-DHAVE_BROKEN_MSVC_CRC32C_HW)
	  message(WARNING "  MSVC version too old; CRC-32C intrinsics broken")
	else()
          add_definitions(-DHAVE_X86_64_CRC32C)
          message(STATUS "  x86_64 CRC-32C intrinsics available")
	endif()
      endif()

      feature_detect(FEATURE_X64CLMUL_FOUND)
      if(FEATURE_X64CLMUL_FOUND)
	add_definitions(-DHAVE_X86_64_CLMUL)
	message(STATUS "  x86_64 CLMUL intrinsics available")
      endif()

      feature_detect(FEATURE_AESNI_FOUND)
      if(FEATURE_AESNI_FOUND)
	add_definitions(-DHAVE_X86_64_AES)
	message(STATUS "  x86_64 AES intrinsics available")
      endif()

      feature_detect(FEATURE_X64SHA1_FOUND)
      if(FEATURE_X64SHA1_FOUND)
	add_definitions(-DHAVE_X86_64_SHA1)
	message(STATUS "  x86_64 SHA-1 intrinsics available")
      endif()

      feature_detect(FEATURE_X64SHA2_FOUND)
      if(FEATURE_X64SHA2_FOUND)
	add_definitions(-DHAVE_X86_64_SHA2)
	message(STATUS "  x86_64 SHA-2 intrinsics available")
      endif()

      feature_detect(FEATURE_AVX_FOUND)
      if(FEATURE_AVX_FOUND)
	add_definitions(-DHAVE_AVX)
	message(STATUS "  x86_64 AVX intrinsics available")

        feature_detect(FEATURE_AVX2_FOUND)
        if(FEATURE_AVX2_FOUND)
  	  add_definitions(-DHAVE_AVX2)
 	  message(STATUS "  x86_64 AVX2 intrinsics available")

	  # Foundational
	  feature_detect(FEATURE_AVX512F_FOUND)
	  if(FEATURE_AVX512F_FOUND)
	    add_definitions(-DHAVE_AVX512_F)
	    message(STATUS "  x86_64 AVX512-F intrinsics available")

	    # Byte and Word
	    feature_detect(FEATURE_AVX512BW_FOUND)
	    if(FEATURE_AVX512BW_FOUND)
	      add_definitions(-DHAVE_AVX512_BW)
	      message(STATUS "  x86_64 AVX512-BW intrinsics available")
	    endif()
	  endif()
        endif()
      endif()
    endif()
  endif()
endif()


if(MSVC)

  feature_detect(FEATURE_UMULH_FOUND)
  if(FEATURE_UMULH_FOUND)
    add_definitions(-DHAVE_UMULH)
    message(STATUS "  x86_64 MSVC high 128-bit multiply intrinsic available")
  endif()

  feature_detect(FEATURE_UMUL128_FOUND)
  if(FEATURE_UMUL128_FOUND)
    add_definitions(-DHAVE_UMUL128)
    message(STATUS "  x86_64 MSVC full 128-bit multiply intrinsic available")
  endif()

else()

  feature_detect(FEATURE_X64ASM_FOUND)
  if(FEATURE_X64ASM_FOUND)
    add_definitions(-DHAVE_X86_64_ASM)
    message(STATUS "  x86_64 __asm__() available")
  endif()

  feature_detect(FEATURE_ARMAES_FOUND)
  if(FEATURE_ARMAES_FOUND)
    add_definitions(-DHAVE_ARM_AES)
    message(STATUS "  ARM AES intrinsics available")
  endif()

  feature_detect(FEATURE_ARMSHA1_FOUND)
  if(FEATURE_ARMSHA1_FOUND)
    add_definitions(-DHAVE_ARM_SHA1)
    message(STATUS "  ARM SHA-1 intrinsics available")
  endif()

  feature_detect(FEATURE_ARMSHA2_FOUND)
  if(FEATURE_ARMSHA2_FOUND)
    add_definitions(-DHAVE_ARM_SHA2)
    message(STATUS "  ARM SHA-2 intrinsics available")
  endif()

  feature_detect(FEATURE_ARMASM32_FOUND)
  if(FEATURE_ARMASM32_FOUND)
    add_definitions(-DHAVE_ARM_ASM)
    message(STATUS "  ARM 32-bit __asm__() available")
  endif()

  feature_detect(FEATURE_ARMASM64_FOUND)
  if(FEATURE_ARMASM64_FOUND)
    add_definitions(-DHAVE_ARM64_ASM)
    message(STATUS "  ARM 64-bit __asm__() available")
  endif()

  feature_detect(FEATURE_PPCVSX_FOUND)
  if(FEATURE_PPCVSX_FOUND)
    add_definitions(-DHAVE_PPC_VSX)
    message(STATUS "  PPC VSX intrinsics available")
  endif()

  feature_detect(FEATURE_PPCAES_FOUND)
  if(FEATURE_PPCAES_FOUND)
    add_definitions(-DHAVE_PPC_AES)
    message(STATUS "  PPC AES intrinsics available")
  endif()

  feature_detect(FEATURE_PPCASM_FOUND)
  if(FEATURE_PPCASM_FOUND)
    add_definitions(-DHAVE_PPC_ASM)
    message(STATUS "  PPC __asm__() available")
  endif()
endif()
