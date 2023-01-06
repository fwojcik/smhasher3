#include <cstdio>
#include <climits>
#include <limits>

#include "curvariant.h"

int main(void) {

    static_assert(std::numeric_limits<int8_t>::min()   == -127-1, "valid int8_t min");
    static_assert(std::numeric_limits<int8_t>::max()   ==  127, "valid int8_t max");
    static_assert(std::numeric_limits<uint8_t>::min()  ==    0, "valid uint8_t min");
    static_assert(std::numeric_limits<uint8_t>::max()  ==  255, "valid uint8_t max");

    static_assert(std::numeric_limits<int16_t>::min()  == -32767-1, "valid int16_t min");
    static_assert(std::numeric_limits<int16_t>::max()  ==  32767, "valid int16_t max");
    static_assert(std::numeric_limits<uint16_t>::min() ==      0, "valid uint16_t min");
    static_assert(std::numeric_limits<uint16_t>::max() ==  65535, "valid uint16_t max");

    static_assert(std::numeric_limits<int32_t>::min()  == -2147483647-1, "valid int32_t min");
    static_assert(std::numeric_limits<int32_t>::max()  ==  2147483647, "valid int32_t max");
    static_assert(std::numeric_limits<uint32_t>::min() ==           0, "valid uint32_t min");
    static_assert(std::numeric_limits<uint32_t>::max() ==  4294967295, "valid uint32_t max");

    static_assert(std::numeric_limits<int64_t>::min()  ==  -9223372036854775807-1, "valid int64_t min");
    static_assert(std::numeric_limits<int64_t>::max()  ==   9223372036854775807, "valid int64_t max");
    static_assert(std::numeric_limits<uint64_t>::min() ==                    0, "valid uint64_t min");
    static_assert(std::numeric_limits<uint64_t>::max() == 18446744073709551615, "valid uint64_t max");

    printf("OK!\n");
}
