########################################
# Endianness and size detection things
########################################

option(ENDIAN_DETECT_BUILDTIME "Try to detect system endianness at build time" ON)

if (ENDIAN_DETECT_BUILDTIME AND (NOT DEFINED DETECTED_LITTLE_ENDIAN))

  # Can't use include (TestBigEndian) because it sometimes does things
  # we don't want, like raising fatal errors or guessing endianness
  # based on machine running cmake.
  # So instead we include the relevant bits here.
  #message(DEBUG "Checking target endianness")

  include(CheckTypeSize)

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
      mark_as_advanced(DETECTED_LITTLE_ENDIAN)
    endif()
  endif()
endif()

# isLE() and isBE() should NOT be constexpr
if(ENDIAN_DETECT_BUILDTIME)
  if(DEFINED DETECTED_LITTLE_ENDIAN)
    if(DETECTED_LITTLE_ENDIAN)
      message(STATUS "Setting target as little-endian")
      set(ENDIAN_IMPL
        "static FORCE_INLINE bool isLE(void) { return true' }\n\
         static FORCE_INLINE bool isBE(void) { return false' }")
    else()
      message(STATUS "Setting target as big-endian")
      set(ENDIAN_IMPL
        "static FORCE_INLINE bool isLE(void) { return false' }\n\
         static FORCE_INLINE bool isBE(void) { return true' }")
    endif()
  else()
    message(WARNING "Cannot detect target endianness; falling back to runtime detection")
  endif()
else()
  message(STATUS "Using runtime endianness detection")
endif()

if(NOT DEFINED ENDIAN_IMPL)
  set(ENDIAN_IMPL
    "static FORCE_INLINE bool isLE(void) {\n\
     const uint32_t   value = 0xb000000e'\n\
     const void *      addr = static_cast<const void *>(&value)'\n\
     const uint8_t *   lsb  = static_cast<const uint8_t *>(addr)'\n\
     return ((*lsb) == 0x0e)'\n }\n\
static FORCE_INLINE bool isBE(void) {\n\
    const uint32_t   value = 0xb000000e'\n\
    const void *      addr = static_cast<const void *>(&value)'\n\
    const uint8_t *   lsb  = static_cast<const uint8_t *>(addr)'\n\
    return ((*lsb) == 0xb0)'\n }\n"
  )
endif()

string(REGEX REPLACE "\n +" "\n" ENDIAN_IMPL ${ENDIAN_IMPL})
string(REGEX REPLACE "'" ";" ENDIAN_IMPL ${ENDIAN_IMPL})
