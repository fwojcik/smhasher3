#define unpredictable(x) __builtin_expect_with_probability(!!(x), 1, 0.5)
