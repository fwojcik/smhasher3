#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#define NSEC_PER_SEC (1000000000ULL)

FORCE_INLINE static uint64_t monotonic_clock(void) {
  LARGE_INTEGER t, f;
  uint64_t result;

  if (QueryPerformanceCounter(&t) == 0)
    return -12;

  QueryPerformanceFrequency(&f);
  result = t.QuadPart / f.QuadPart * NSEC_PER_SEC;
  if (f.QuadPart > NSEC_PER_SEC) {
      result += (t.QuadPart % f.QuadPart) / (f.QuadPart / NSEC_PER_SEC);
  } else {
      result += (t.QuadPart % f.QuadPart) * (NSEC_PER_SEC / f.QuadPart);
  }
  return result;
}
