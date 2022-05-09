########################################
# Fixed-width integer type detection
########################################

message(STATUS "Probing fixed-width integer variants")

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
  "${FIXEDINT_IMPL}\n"
  3
)
findVariant(FIXEDINT_SEEDT)
