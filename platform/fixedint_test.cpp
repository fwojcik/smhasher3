#include <cstdio>
#include <climits>
#include <limits>

#include "curvariant.h"

int main(void) {

    static_assert(std::numeric_limits<int8_t>::min()   == -127-1);
    static_assert(std::numeric_limits<int8_t>::max()   ==  127);
    static_assert(std::numeric_limits<uint8_t>::min()  ==    0);
    static_assert(std::numeric_limits<uint8_t>::max()  ==  255);

    static_assert(std::numeric_limits<int16_t>::min()  == -32767-1);
    static_assert(std::numeric_limits<int16_t>::max()  ==  32767);
    static_assert(std::numeric_limits<uint16_t>::min() ==      0);
    static_assert(std::numeric_limits<uint16_t>::max() ==  65535);

    static_assert(std::numeric_limits<int32_t>::min()  == -2147483647-1);
    static_assert(std::numeric_limits<int32_t>::max()  ==  2147483647);
    static_assert(std::numeric_limits<uint32_t>::min() ==           0);
    static_assert(std::numeric_limits<uint32_t>::max() ==  4294967295);

    static_assert(std::numeric_limits<int64_t>::min()  ==  -9223372036854775807-1);
    static_assert(std::numeric_limits<int64_t>::max()  ==   9223372036854775807);
    static_assert(std::numeric_limits<uint64_t>::min() ==                    0);
    static_assert(std::numeric_limits<uint64_t>::max() == 18446744073709551615);

    printf("OK!\n");
}
