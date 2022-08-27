#define VECTOR_SHUFFLE_1(vec, shf) __builtin_shuffle(vec, shf)
#define VECTOR_SHUFFLE_2(vec1, vec2, shf) __builtin_shuffle(vec1, vec2, shf)
#define HAVE_GENERIC_VECTOR_SHUFFLE
