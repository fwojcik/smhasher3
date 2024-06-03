/*
 * Copyright (C) 2021-2023 Frank J. T. Wojcik
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <https://www.gnu.org/licenses/>.
 */
#define BARE_RNG
#include "Random.cpp"

#include <cstdlib>
#include <cstdio>

unsigned STRIDE = 16;

void usage(void) {
    printf("A simple program to spit out bytes from Rand::rand_u64().\n");
    printf("\n");
    printf("Usage:\n");
    printf("    rngstream gen_type [base_seed [base_stream [stride]]]\n");
    printf("\n");
    printf("  The default values for base_seed is 0.\n");
    printf("\n");
    printf("  Valid values for gen_type:\n");
    printf("    1\t\tBytes from 1 seed for default stream\n");
    printf("    2\t\tBytes from 1 seed across many substreams\n");
    printf("    3\t\tBytes from many seeds across default stream\n");
    printf("    4\t\tBytes from many seeds across many substreams\n");
    printf("\n");
    printf("  The stride parameter defines how many random u64s are\n");
    printf("  written before incrementing to the next (seed, substream)\n");
    printf("  configuration. The default value is %u.\n", STRIDE);
    printf("  Note that stride is meaningless when gen_type is 1.\n");
    exit(0);
}

/*
 * Simple program that turns Rand::rand_u64() into a raw byte stream, for
 * use with dieharder or other RNG testing programs.
 */
int main(int argc, char * argv[]) {
    uint64_t mode, seed, stream, usestream;

    if ((argc < 2) || (argc > 5)) {
        usage();
    }

    // Arbitrary default values
    seed = 0;
    stream = 0;
    usestream = 0;

    if ((argv[1][0] >= '1') && (argv[1][0] <= '4')) {
        mode = argv[1][0] - '0';
    } else {
        usage();
    }

    if ((mode == 2) || (mode == 4)) {
        usestream = 1;
    }

    if (argc >= 3) {
        char * endptr;
        seed = strtoul(argv[2], &endptr, 0);
        if ((argv[2][0] == '\0') || (*endptr != '\0')) {
            printf("Can't parse seed: %s\n", argv[2]);
            usage();
        }
        if (argc >= 4) {
            stream = strtoul(argv[3], &endptr, 0);
            if ((argv[3][0] == '\0') || (*endptr != '\0')) {
                printf("Can't parse stream: %s\n", argv[3]);
                usage();
            }
            usestream = 1;
            if (argc >= 5) {
                unsigned val = strtoul(argv[4], &endptr, 0);
                if ((argv[4][0] == '\0') || (*endptr != '\0')) {
                    printf("Can't parse stride: %s\n", argv[4]);
                    usage();
                }
                if (val == 0) {
                    printf("Stride cannot be 0!\n");
                    usage();
                }
                STRIDE = val;
            }
        }
    }

    Rand RNG;
    uint64_t r;

    if (usestream) {
        RNG.reseed({seed, stream});
    } else {
        RNG.reseed(seed);
    }

#define WRITE_NEXT()                                        \
    r = RNG.rand_u64();                                     \
    if (fwrite(&r, sizeof(r), 1, stdout) != 1) { exit(1); }

    while (1) {
        switch (mode) {
        case 1:
            WRITE_NEXT();
            break;
        case 2:
            for (unsigned i = 0; i < STRIDE; i++) {
                WRITE_NEXT();
            }
            RNG.reseed({seed, ++stream});
            break;
        case 3:
            for (unsigned i = 0; i < STRIDE; i++) {
                WRITE_NEXT();
            }
            if (usestream) {
                RNG.reseed({++seed, stream});
            } else {
                RNG.reseed(++seed);
            }
            break;
        case 4:
            for (unsigned i = 0; i < STRIDE; i++) {
                uint64_t basestream = stream;
                for (unsigned j = 0; j < STRIDE; j++) {
                    for (unsigned k = 0; k < STRIDE; k++) {
                        WRITE_NEXT();
                    }
                    RNG.reseed({seed, ++stream});
                }
                stream = basestream;
                RNG.reseed({++seed, stream});
            }
            stream += STRIDE;
            break;
        }
    }
}
