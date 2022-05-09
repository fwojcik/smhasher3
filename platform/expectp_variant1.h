#define expectp(x,p) __builtin_expect_with_probability(!!(x), 1, (p))
