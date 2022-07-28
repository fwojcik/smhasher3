########################################
# Fixed-width integer type detection
########################################

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
  set(HAVE_32BIT_PLATFORM TRUE)
else()
  set(HAVE_32BIT_PLATFORM FALSE)
endif()

checkCachedVarsDepend(FIXEDINT "fixed-width integer variants")

# Tell findVariant() where to store the files and variables it touches
set(VARIANT_VARLISTVAR  "FIXEDINT_VARLIST")
set(VARIANT_FILELISTVAR "FIXEDINT_FILELIST")

set(FIXEDINT_VARIANTS
  "signed and unsigned 8,16,32,64-bit integers"
  "fixedint"
  "\n"
  5
)
findVariant(FIXEDINT)

set(FIXEDINT_128_VARIANTS
  "signed and unsigned 128-bit integers"
  "fixedint128"
  "\n"
  2
)
findVariant(FIXEDINT_128)

set(FIXEDINT_SEEDT_VARIANTS
  "appropriate type for seed_t"
  "seedt"
  "@FIXEDINT_IMPL@\n"
  3
)
findVariant(FIXEDINT_SEEDT)

# By depending on this .cmake file, the cache will be cleared if the
# list of files were to ever change, as this file is the only one that
# can change it.
list(APPEND FIXEDINT_FILELIST "${DETECT_DIR}/intsize.cmake")

setCachedVarsDepend(FIXEDINT FIXEDINT_VARLIST FIXEDINT_FILELIST)
