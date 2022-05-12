#include <time.h>
#include <sys/time.h>

#define NSEC_PER_SEC 1000000000ULL

FORCE_INLINE static uint64_t monotonic_clock(void) {
  struct timespec ts;
  uint64_t result;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return -10;

  result = ts.tv_sec * NSEC_PER_SEC;
  result += ts.tv_nsec;

  return result;
}
