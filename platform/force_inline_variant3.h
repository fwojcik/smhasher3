#define FORCE_INLINE \
    _Pragma("FUNC_ALWAYS_INLINE;")\
    _Pragma("inline=forced")\
    inline
