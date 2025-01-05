########################################
# Instruction set availability detection
########################################

### Find header files

include(CheckIncludeFileCXX)

if(PROCESSOR_FAMILY STREQUAL "Arm")
  check_include_file_cxx("arm_neon.h" HAVE_ARM_NEON)
  if(HAVE_ARM_NEON)
    message(STATUS "ARM NEON available")
  endif()
  check_include_file_cxx("arm_acle.h" HAVE_ARM_ACLE)
  if(HAVE_ARM_ACLE)
    message(STATUS "ARM ACLE available")
  endif()
elseif(PROCESSOR_FAMILY STREQUAL "x86")
  check_include_file_cxx("immintrin.h" HAVE_IMMINTRIN)
  if(HAVE_IMMINTRIN)
    check_include_file_cxx("x86intrin.h" HAVE_X86INTRIN)
    if(HAVE_X86INTRIN)
      message(STATUS "x86 universal intrinsic header available")
    else()
      check_include_file_cxx("ammintrin.h" HAVE_AMMINTRIN)
      if(HAVE_AMMINTRIN)
        message(STATUS "x86 Intel and AMD intrinsic headers available")
      else()
        message(STATUS "x86 intrinsic header available")
      endif()
    endif()
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
  HAVE_SSE_2             x86_64_sse2.cpp
  HAVE_GOOD_LOADU_32     x86_64_loadu_32.cpp
  HAVE_GOOD_LOADU_64     x86_64_loadu_64.cpp
  HAVE_SSSE_3            x86_64_ssse3.cpp
  HAVE_SSE_4_1           x86_64_sse41.cpp
  HAVE_XOP               x86_64_xop.cpp
  HAVE_X86_64_CRC32C     x86_64_crc.cpp
  HAVE_X86_64_CLMUL      x86_64_clmul.cpp
  HAVE_X86_64_AES        x86_64_aes.cpp
  HAVE_X86_64_SHA1       x86_64_sha1.cpp
  HAVE_X86_64_SHA2       x86_64_sha2.cpp
  HAVE_AVX               x86_64_avx.cpp
  HAVE_AVX2              x86_64_avx2.cpp
  HAVE_AVX512_F          x86_64_avx512_f.cpp
  HAVE_AVX512_BW         x86_64_avx512_bw.cpp
  HAVE_AVX512_VL         x86_64_avx512_vl.cpp
  HAVE_UMULH             x86_64_umulh.cpp
  HAVE_UMUL128           x86_64_umul128.cpp
  HAVE_X86_64_ASM        x86_64_asm.cpp
  HAVE_ARM_AES           arm_aes.cpp
  HAVE_ARM_SHA1          arm_neon_sha1.cpp
  HAVE_ARM_SHA2          arm_neon_sha2.cpp
  HAVE_ARM_ASM           arm_asm.cpp
  HAVE_ARM64_ASM         arm_asm64.cpp
  HAVE_PPC_VSX           ppc_vsx.cpp
  HAVE_PPC_AES           ppc_aes.cpp
  HAVE_PPC_ASM           ppc_asm.cpp
)

# Function for detection of features via try_compile(), with caching
# of results. try_compile() implicitly caches the result var value,
# but if any of the detection input files change, then the variables
# will be cleared via setVarsDepend() below.
function(feature_detect var)
  if (NOT DEFINED ${var})
    lookupDetectFile(file ${var})
    if(MSVC AND NOT CMAKE_CXX_COMPILER_ID STREQUAL Clang)
      try_run(MSVC_RUN_OK MSVC_COMPILE_OK ${CMAKE_BINARY_DIR} ${DETECT_DIR}/${file}
        CMAKE_FLAGS "-DINCLUDE_DIRECTORIES=${CMAKE_SOURCE_DIR}/include/common;${CMAKE_BINARY_DIR}/include/"
        OUTPUT_VARIABLE dump
      )
      # The result from try_run() is inverted from what we want
      if(MSVC_RUN_OK EQUAL 0)
        set(${var} TRUE PARENT_SCOPE)
      else()
        set(${var} FALSE PARENT_SCOPE)
      endif()
    else()
      try_compile(${var} ${CMAKE_BINARY_DIR} ${DETECT_DIR}/${file}
        CMAKE_FLAGS "-DINCLUDE_DIRECTORIES=${CMAKE_SOURCE_DIR}/include/common;${CMAKE_BINARY_DIR}/include/"
        OUTPUT_VARIABLE dump
      )
    endif()
    #message(STATUS "Got result ${dump} for ${file}")
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
#
# Unlike in the other .cmake files in platform/, the list of files and
# variables can be computed "up-front" here, so the
# setCachedVarsDepend() call doesn't need to wait until the end.

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
# These also depend on the fixed-size int implementation
list(APPEND detectFiles "${DETECT_DIR}/intsize.cmake")
# These also depend on the force-inline builtin implementation
list(APPEND detectFiles "${DETECT_DIR}/builtins.cmake")

checkCachedVarsDepend(DETECT "instruction-set availability")
setCachedVarsDepend(DETECT detectVars detectFiles)

########################################

# Write out the necessary headers for testing intrinsics
string(CONFIGURE "\
@FIXEDINT_IMPL@\n\
@FORCE_INLINE_IMPL@\n\
#cmakedefine HAVE_ARM_NEON\n\
#cmakedefine HAVE_ARM_ACLE\n\
#cmakedefine HAVE_IMMINTRIN\n\
#cmakedefine HAVE_AMMINTRIN\n\
#cmakedefine HAVE_X86INTRIN\n\
#include \"Intrinsics.h\"\n"
  PREAMBLE @ONLY)
file(WRITE ${CMAKE_BINARY_DIR}/include/isa.h "${PREAMBLE}")

########################################

feature_detect(HAVE_SSE_2)
if(HAVE_SSE_2)
  message(STATUS "  x86_64 SSE 2 intrinsics available")

  feature_detect(HAVE_GOOD_LOADU_32)
  if(HAVE_GOOD_LOADU_32)
    message(STATUS "  x86_64 16- and 32-bit loadu intrinsics available")
  else()
    message(STATUS "  x86_64 16- and 32-bit loadu intrinsics unavailable; using fallbacks")
  endif()

  feature_detect(HAVE_GOOD_LOADU_64)
  if(HAVE_GOOD_LOADU_64)
    message(STATUS "  x86_64 64-bit loadu intrinsics available")
  else()
    message(STATUS "  x86_64 64-bit loadu intrinsics unavailable; using fallbacks")
  endif()

  feature_detect(HAVE_SSSE_3)
  if(HAVE_SSSE_3)
    message(STATUS "  x86_64 SSSE3 intrinsics available")

    feature_detect(HAVE_SSE_4_1)
    if(HAVE_SSE_4_1)
      message(STATUS "  x86_64 SSE 4.1 intrinsics available")

      feature_detect(HAVE_XOP)
      if(HAVE_XOP)
	message(STATUS "  x86_64 XOP intrinsics available")
      endif()

      feature_detect(HAVE_X86_64_CRC32C)
      if(HAVE_X86_64_CRC32C)
        # This allegedly falls into a MSVC CL 14.16.27023 32-bit
        # compiler bug. 14.28.29910 allegedly works fine.
        if (MSVC AND (CMAKE_SIZEOF_VOID_P EQUAL 4) AND (MSVC_VERSION LESS 1928))
	  unset(HAVE_X86_64_CRC32C)
	  message(WARNING "  MSVC version too old; CRC-32C intrinsics broken")
	else()
          message(STATUS "  x86_64 CRC-32C intrinsics available")
	endif()
      endif()

      feature_detect(HAVE_X86_64_CLMUL)
      if(HAVE_X86_64_CLMUL)
	message(STATUS "  x86_64 CLMUL intrinsics available")
      endif()

      feature_detect(HAVE_X86_64_AES)
      if(HAVE_X86_64_AES)
	message(STATUS "  x86_64 AES intrinsics available")
      endif()

      feature_detect(HAVE_X86_64_SHA1)
      if(HAVE_X86_64_SHA1)
	message(STATUS "  x86_64 SHA-1 intrinsics available")
      endif()

      feature_detect(HAVE_X86_64_SHA2)
      if(HAVE_X86_64_SHA2)
	message(STATUS "  x86_64 SHA-2 intrinsics available")
      endif()

      feature_detect(HAVE_AVX)
      if(HAVE_AVX)
	message(STATUS "  x86_64 AVX intrinsics available")

        feature_detect(HAVE_AVX2)
        if(HAVE_AVX2)
 	  message(STATUS "  x86_64 AVX2 intrinsics available")

	  # Foundational
	  feature_detect(HAVE_AVX512_F)
	  if(HAVE_AVX512_F)
	    message(STATUS "  x86_64 AVX512-F intrinsics available")

	    # Byte and Word
	    feature_detect(HAVE_AVX512_BW)
	    if(HAVE_AVX512_BW)
	      message(STATUS "  x86_64 AVX512-BW intrinsics available")
	    endif()

	    # Vector Length
	    feature_detect(HAVE_AVX512_VL)
	    if(HAVE_AVX512_VL)
	      message(STATUS "  x86_64 AVX512-VL intrinsics available")
	    endif()
	  endif()
        endif()
      endif()
    endif()
  endif()
endif()

if(MSVC)

  feature_detect(HAVE_UMULH)
  if(HAVE_UMULH)
    message(STATUS "  x86_64 MSVC high 128-bit multiply intrinsic available")
  endif()

  feature_detect(HAVE_UMUL128)
  if(HAVE_UMUL128)
    message(STATUS "  x86_64 MSVC full 128-bit multiply intrinsic available")
  endif()

else()

  # For the moment, I'm leaving all of these detections enabled on all
  # platforms. This is to maybe accommodate future inclusions of
  # SIMD-everywhere or similar intrinsic emulation headers. This may
  # change in the future.

  feature_detect(HAVE_X86_64_ASM)
  if(HAVE_X86_64_ASM)
    message(STATUS "  x86_64 __asm__() available")
  endif()

  feature_detect(HAVE_ARM_AES)
  if(HAVE_ARM_AES)
    message(STATUS "  ARM AES intrinsics available")
  endif()

  feature_detect(HAVE_ARM_SHA1)
  if(HAVE_ARM_SHA1)
    message(STATUS "  ARM SHA-1 intrinsics available")
  endif()

  feature_detect(HAVE_ARM_SHA2)
  if(HAVE_ARM_SHA2)
    message(STATUS "  ARM SHA-2 intrinsics available")
  endif()

  feature_detect(HAVE_ARM_ASM)
  if(HAVE_ARM_ASM)
    message(STATUS "  ARM 32-bit __asm__() available")
  endif()

  feature_detect(HAVE_ARM64_ASM)
  if(HAVE_ARM64_ASM)
    message(STATUS "  ARM 64-bit __asm__() available")
  endif()

  feature_detect(HAVE_PPC_VSX)
  if(HAVE_PPC_VSX)
    message(STATUS "  PPC VSX intrinsics available")
  endif()

  feature_detect(HAVE_PPC_AES)
  if(HAVE_PPC_AES)
    message(STATUS "  PPC AES intrinsics available")
  endif()

  feature_detect(HAVE_PPC_ASM)
  if(HAVE_PPC_ASM)
    message(STATUS "  PPC __asm__() available")
  endif()
endif()
