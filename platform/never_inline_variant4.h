#define NEVER_INLINE \
    _Pragma("FUNC_CANNOT_INLINE;")\
    _Pragma("inline=never")\
    _Pragma("noinline")\

