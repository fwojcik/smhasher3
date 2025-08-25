########################################
# Various compiler hints and bit manipulations
########################################

checkCachedVarsDepend(BUILTINS "compiler builtin function variants")

# Tell findVariant() where to store the files and variables it touches
set(VARIANT_VARLISTVAR  "BUILTINS_VARLIST")
set(VARIANT_FILELISTVAR "BUILTINS_FILELIST")

set(LIKELY_VARIANTS
  "likely() / unlikely()"
  "expect"
  "\n"
  3
)
findVariant(LIKELY)

set(EXPECTP_VARIANTS
  "expectp()"
  "expectp"
  "@LIKELY_IMPL@\n"
  3
)
# If we don't have useful likely()/unlikely() macros, then don't
# bother with the expectp() variant that uses them.
if(LIKELY_FALLBACK)
  list(APPEND EXPECTP_VARIANTS 2)
endif()
findVariant(EXPECTP)

# Fallback to 2 if fallback on EXPECTP_IMPL, or 3 if not?
set(UNPREDICT_VARIANTS
  "unpredictable()"
  "unpredictable"
  "\n"
  3
)
findVariant(UNPREDICT)

set(UNREACHABLE_VARIANTS
  "unreachable()"
  "unreachable"
  "#define assume(x)\n"
  2
)
findVariant(UNREACHABLE)

set(ASSUME_VARIANTS
  "assume()"
  "assume"
  "@UNREACHABLE_IMPL@\n"
  5
)
# If there's no real unreachable(), then delete that variant option
if(UNREACHABLE_FALLBACK)
  list(APPEND ASSUME_VARIANTS 4)
endif()
findVariant(ASSUME)

set(PREFETCH_VARIANTS
  "prefetch()"
  "prefetch"
  "\n"
  2
)
findVariant(PREFETCH)

set(FORCE_INLINE_VARIANTS
  "forcing function inlining"
  "force_inline"
  "\n"
  4
)
findVariant(FORCE_INLINE)

set(NEVER_INLINE_VARIANTS
  "preventing function inlining"
  "never_inline"
  "\n"
  5
)
findVariant(NEVER_INLINE)

set(RESTRICT_VARIANTS
  "C++ restrict keyword replacement"
  "restrict"
  "\n"
  2
)
findVariant(RESTRICT)

set(MAY_ALIAS_VARIANTS
  "type aliasing attribute"
  "may_alias"
  "@FIXEDINT_IMPL@\n"
  2
)
findVariant(MAY_ALIAS)

set(ROT32_VARIANTS
  "32-bit integer rotation"
  "rot32"
  "@FIXEDINT_IMPL@\n"
  3
)
findVariant(ROT32)

set(ROT64_VARIANTS
  "64-bit integer rotation"
  "rot64"
  "@FIXEDINT_IMPL@\n"
  4
)
findVariant(ROT64)

set(BSWAP_VARIANTS
  "Integer byteswapping"
  "bswap"
  "@FIXEDINT_IMPL@\n"
  3
)
findVariant(BSWAP)

set(POPCOUNT32_VARIANTS
  "32-bit integer popcount"
  "popcount32"
  "@FIXEDINT_IMPL@\n"
  3
)
findVariant(POPCOUNT32)

set(POPCOUNT64_VARIANTS
  "64-bit integer popcount"
  "popcount64"
  "@FIXEDINT_IMPL@\n"
  6
)
findVariant(POPCOUNT64)

set(CLZ32_VARIANTS
  "32-bit integer count leading zero bits"
  "clz32"
  "@FIXEDINT_IMPL@\n"
  4
)
findVariant(CLZ32)

set(CLZ64_VARIANTS
  "64-bit integer count leading zero bits"
  "clz64"
  "@FIXEDINT_IMPL@\n"
  6
)
findVariant(CLZ64)

# For this one, fallback really means "unsupported".
# Users should check against HAVE_GENERIC_VECTOR.
set(VECTOR_VARIANTS
  "Generic vector types"
  "vector"
  "\n"
  2
)
findVariant(VECTOR)

if(NOT VECTOR_FALLBACK)
  set(SHUFFLE_VARIANTS
    "Integer shuffling"
    "shuffle"
    "@VECTOR_IMPL@\n"
    2
  )
  findVariant(SHUFFLE)
endif()

# By depending on this .cmake file, the cache will be cleared if the
# list of files were to ever change, as this file is the only one that
# can change it.
list(APPEND BUILTINS_FILELIST "${DETECT_DIR}/builtins.cmake")
# These also depend on the fixed-size int implementation
list(APPEND BUILTINS_FILELIST "${DETECT_DIR}/intsize.cmake")

setCachedVarsDepend(BUILTINS BUILTINS_VARLIST BUILTINS_FILELIST)
