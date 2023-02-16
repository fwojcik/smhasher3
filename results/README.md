SMHasher3 results summary
=========================

[[_TOC_]]

Passing hashes
--------------

Hashes that currently pass all tests, sorted by average short input speed.

| Hash name | output width | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-----------:|-------------------------:|------------------------:|
| [komihash](komihash.txt) | 64 | 246 |  38.95 |   6.33|
| [khashv-32](khashv-32.txt) | 32 | 246 |  61.47 |   2.97|
| [SpookyHash1-32](SpookyHash1-32.txt) | 32 | 246 |  64.86 |   4.40|
| [SpookyHash2-32](SpookyHash2-32.txt) | 32 | 246 |  66.29 |   4.40|
| [MeowHash.64](MeowHash.64.txt) | 64 | 246 |  67.49 |  12.37|
| [MeowHash](MeowHash.txt) | 128 | 246 |  67.54 |  12.39|
| [MeowHash.32](MeowHash.32.txt) | 32 | 246 |  67.54 |  12.19|
| [CityMurmur.seed1](CityMurmur.seed1.txt) | 128 | 246 |  74.37 |   2.61|
| [CityMurmur.seed3](CityMurmur.seed3.txt) | 128 | 246 |  74.47 |   2.61|
| [FarmHash-128.CM.seed1](FarmHash-128.CM.seed1.txt) | 128 | 246 |  74.66 |   2.61|
| [FarmHash-128.CM.seed3](FarmHash-128.CM.seed3.txt) | 128 | 246 |  75.51 |   2.61|
| [HalfSipHash](HalfSipHash.txt) | 32 | 234 |  88.16 |   0.35|
| [GoodOAAT](GoodOAAT.txt) | 32 | 231 |  92.52 |   0.24|
| [chaskey-8.32](chaskey-8.32.txt) | 32 | 234 |  99.88 |   0.37|
| [chaskey-8.64](chaskey-8.64.txt) | 64 | 234 | 100.13 |   0.37|
| [hasshe2.tweaked](hasshe2.tweaked.txt) | 256 | 234 | 103.42 |   0.92|
| [PearsonBlock-64](PearsonBlock-64.txt) | 64 | 234 | 107.19 |   0.57|
| [chaskey-8](chaskey-8.txt) | 128 | 234 | 108.51 |   0.37|
| [PearsonBlock-128](PearsonBlock-128.txt) | 128 | 234 | 115.47 |   0.53|
| [SipHash-1-3](SipHash-1-3.txt) | 64 | 234 | 116.26 |   0.60|
| [chaskey-12.32](chaskey-12.32.txt) | 32 | 231 | 130.10 |   0.25|
| [chaskey-12.64](chaskey-12.64.txt) | 64 | 231 | 130.89 |   0.25|
| [chaskey-12](chaskey-12.txt) | 128 | 231 | 139.40 |   0.25|
| [SipHash-2-4](SipHash-2-4.txt) | 64 | 231 | 158.75 |   0.31|
| [PearsonBlock-256](PearsonBlock-256.txt) | 256 | 234 | 174.63 |   0.33|
| [CityHashCrc-256](CityHashCrc-256.txt) | 256 | 234 | 190.61 |   5.31|
| [prvhash-64.incr](prvhash-64.incr.txt) | 64 | 234 | 193.47 |   2.29|
| [Discohash.old](Discohash.old.txt) | 64 | 234 | 214.09 |   1.34|
| [prvhash-128.incr](prvhash-128.incr.txt) | 128 | 234 | 285.55 |   2.16|
| [blake3](blake3.txt) | 256 | 231 | 322.69 |   0.42|
| [SHA-2-224](SHA-2-224.txt) | 224 | 231 | 331.53 |   0.45|
| [ascon-XOFa-32](ascon-XOFa-32.txt) | 32 | 231 | 394.70 |   0.08|
| [ascon-XOFa-64](ascon-XOFa-64.txt) | 64 | 231 | 395.24 |   0.08|
| [SHA-2-224.64](SHA-2-224.64.txt) | 64 | 231 | 412.19 |   0.45|
| [SHA-2-256.64](SHA-2-256.64.txt) | 64 | 231 | 412.19 |   0.45|
| [SHA-2-256](SHA-2-256.txt) | 256 | 231 | 433.54 |   0.45|
| [blake2s-256.64](blake2s-256.64.txt) | 64 | 231 | 433.76 |   0.17|
| [blake2s-256](blake2s-256.txt) | 256 | 231 | 436.21 |   0.17|
| [blake2s-160](blake2s-160.txt) | 160 | 231 | 436.46 |   0.17|
| [blake2s-128](blake2s-128.txt) | 128 | 231 | 436.60 |   0.17|
| [blake2s-224](blake2s-224.txt) | 224 | 231 | 456.21 |   0.17|
| [ascon-XOF-32](ascon-XOF-32.txt) | 32 | 231 | 484.17 |   0.05|
| [ascon-XOF-64](ascon-XOF-64.txt) | 64 | 231 | 485.32 |   0.05|
| [RIPEMD-128](RIPEMD-128.txt) | 128 | 231 | 491.35 |   0.15|
| [SHA-1](SHA-1.txt) | 128 | 231 | 497.21 |   0.48|
| [SHA-1.64](SHA-1.64.txt) | 64 | 231 | 497.24 |   0.48|
| [SHA-1.32](SHA-1.32.txt) | 32 | 231 | 498.21 |   0.48|
| [ascon-XOFa-128](ascon-XOFa-128.txt) | 128 | 231 | 502.37 |   0.08|
| [MD5](MD5.txt) | 128 | 231 | 526.20 |   0.14|
| [MD5.64](MD5.64.txt) | 64 | 231 | 527.14 |   0.14|
| [MD5.32](MD5.32.txt) | 32 | 231 | 527.19 |   0.14|
| [RIPEMD-256](RIPEMD-256.txt) | 256 | 231 | 570.34 |   0.13|
| [blake2b-256](blake2b-256.txt) | 256 | 231 | 587.26 |   0.26|
| [blake2b-256.64](blake2b-256.64.txt) | 64 | 231 | 589.66 |   0.26|
| [blake2b-128](blake2b-128.txt) | 128 | 231 | 590.91 |   0.26|
| [blake2b-160](blake2b-160.txt) | 160 | 231 | 590.96 |   0.26|
| [blake2b-224](blake2b-224.txt) | 224 | 231 | 610.41 |   0.26|
| [ascon-XOFa-160](ascon-XOFa-160.txt) | 160 | 231 | 625.61 |   0.08|
| [ascon-XOF-128](ascon-XOF-128.txt) | 128 | 231 | 643.79 |   0.05|
| [RIPEMD-160](RIPEMD-160.txt) | 160 | 231 | 719.77 |   0.10|
| [ascon-XOFa-224](ascon-XOFa-224.txt) | 224 | 231 | 740.28 |   0.08|
| [ascon-XOFa-256](ascon-XOFa-256.txt) | 256 | 231 | 740.39 |   0.08|
| [ascon-XOF-160](ascon-XOF-160.txt) | 160 | 231 | 812.58 |   0.05|
| [ascon-XOF-224](ascon-XOF-224.txt) | 224 | 231 | 981.78 |   0.05|
| [ascon-XOF-256](ascon-XOF-256.txt) | 256 | 231 | 983.90 |   0.05|
| [SHA-3](SHA-3.txt) | 256 | 231 | 2980.59 |   0.05|
| [SHA-3-256.64](SHA-3-256.64.txt) | 64 | 231 | 2984.17 |   0.05|


Failing hashes
--------------

Hashes that pass Sanity tests, but fail others, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [t1ha2-128](t1ha2-128.txt) | 128 | 1 | 246 |  67.84 |   4.89|
| [wyhash-32](wyhash-32.txt) | 32 | 2 | 246 |  37.00 |   1.33|
| [FarmHash-128.CC.seed1](FarmHash-128.CC.seed1.txt) | 128 | 2 | 246 |  74.26 |   4.84|
| [CityHash-128.seed1](CityHash-128.seed1.txt) | 128 | 2 | 246 |  74.43 |   4.84|
| [CityHash-128.seed3](CityHash-128.seed3.txt) | 128 | 2 | 246 |  74.48 |   4.85|
| [FarmHash-128.CC.seed3](FarmHash-128.CC.seed3.txt) | 128 | 2 | 246 |  75.91 |   4.84|
| [t1ha2-64](t1ha2-64.txt) | 64 | 3 | 246 |  47.13 |   4.62|
| [SpookyHash2-64](SpookyHash2-64.txt) | 64 | 3 | 246 |  66.29 |   4.40|
| [beamsplitter](beamsplitter.txt) | 64 | 4 | 231 | 924.46 |   0.18|
| [t1ha0.aesA](t1ha0.aesA.txt) | 64 | 5 | 246 |  47.09 |   9.09|
| [t1ha0.aesB](t1ha0.aesB.txt) | 64 | 5 | 246 |  47.25 |  21.35|
| [khashv-64](khashv-64.txt) | 64 | 5 | 246 |  59.44 |   2.97|
| [SpookyHash1-64](SpookyHash1-64.txt) | 64 | 5 | 246 |  64.85 |   4.40|
| [pengyhash](pengyhash.txt) | 64 | 5 | 246 |  76.64 |   4.62|
| [falkhash2](falkhash2.txt) | 128 | 6 | 246 |  91.90 |  18.40|
| [FarmHash-32.NT](FarmHash-32.NT.txt) | 32 | 7 | 246 |  57.82 |   7.78|
| [CityHashCrc-128.seed1](CityHashCrc-128.seed1.txt) | 128 | 7 | 246 |  74.75 |   5.30|
| [CityHashCrc-128.seed3](CityHashCrc-128.seed3.txt) | 128 | 7 | 246 |  74.78 |   5.31|
| [FarmHash-128.CM.seed2](FarmHash-128.CM.seed2.txt) | 128 | 8 | 246 |  74.65 |   2.61|
| [CityMurmur.seed2](CityMurmur.seed2.txt) | 128 | 8 | 246 |  74.68 |   2.61|
| [XXH-64](XXH-64.txt) | 64 | 9 | 246 |  58.73 |   3.99|
| [FarmHash-128.CC.seed2](FarmHash-128.CC.seed2.txt) | 128 | 10 | 246 |  74.27 |   4.82|
| [CityHash-128.seed2](CityHash-128.seed2.txt) | 128 | 10 | 246 |  74.65 |   4.84|
| [falkhash1](falkhash1.txt) | 128 | 10 | 246 |  89.89 |  19.82|
| [wyhash](wyhash.txt) | 64 | 11 | 246 |  35.31 |   6.97|
| [wyhash.strict](wyhash.strict.txt) | 64 | 11 | 246 |  37.12 |   5.77|
| [TinySipHash](TinySipHash.txt) | 64 | 13 | 246 |  47.75 |   1.50|
| [SpookyHash2-128](SpookyHash2-128.txt) | 128 | 13 | 246 |  70.56 |   4.40|
| [SpookyHash1-128](SpookyHash1-128.txt) | 128 | 14 | 246 |  69.29 |   4.40|
| [CityHashCrc-128.seed2](CityHashCrc-128.seed2.txt) | 128 | 14 | 246 |  74.79 |   5.31|
| [XXH3-64.regen](XXH3-64.regen.txt) | 64 | 15 | 246 |  36.23 |  12.76|
| [mum1.inexact.unroll2](mum1.inexact.unroll2.txt) | 64 | 16 | 246 |  52.58 |   1.20|
| [XXH3-128.regen](XXH3-128.regen.txt) | 128 | 16 | 246 |  64.31 |  12.68|
| [floppsyhash](floppsyhash.txt) | 64 | 16 | 231 | 739.99 |   0.05|
| [mum1.inexact.unroll3](mum1.inexact.unroll3.txt) | 64 | 17 | 246 |  52.95 |   1.31|
| [mum1.inexact.unroll4](mum1.inexact.unroll4.txt) | 64 | 17 | 246 |  53.05 |   1.86|
| [mir.inexact](mir.inexact.txt) | 64 | 17 | 246 |  54.62 |   1.33|
| [mum1.inexact.unroll1](mum1.inexact.unroll1.txt) | 64 | 17 | 246 |  56.40 |   1.14|
| [MetroHash-128](MetroHash-128.txt) | 128 | 17 | 246 |  59.09 |   5.09|
| [mum1.exact.unroll4](mum1.exact.unroll4.txt) | 64 | 18 | 246 |  40.22 |   3.93|
| [mum1.exact.unroll3](mum1.exact.unroll3.txt) | 64 | 18 | 246 |  40.54 |   4.34|
| [mum1.exact.unroll2](mum1.exact.unroll2.txt) | 64 | 18 | 246 |  40.58 |   4.25|
| [mum1.exact.unroll1](mum1.exact.unroll1.txt) | 64 | 18 | 246 |  42.57 |   2.58|
| [mir.exact](mir.exact.txt) | 64 | 18 | 246 |  43.89 |   2.13|
| [t1ha0](t1ha0.txt) | 64 | 18 | 246 |  51.38 |   2.42|
| [t1ha2-64.incr](t1ha2-64.incr.txt) | 64 | 18 | 246 |  85.48 |   4.86|
| [FARSH-32.tweaked](FARSH-32.tweaked.txt) | 32 | 19 | 246 |  69.96 |  16.02|
| [MetroHash-128.var1](MetroHash-128.var1.txt) | 128 | 20 | 246 |  59.10 |   5.08|
| [FARSH-64.tweaked](FARSH-64.tweaked.txt) | 64 | 20 | 246 | 122.28 |   7.87|
| [Discohash](Discohash.txt) | 64 | 21 | 234 | 233.56 |   1.34|
| [FARSH-256.tweaked](FARSH-256.tweaked.txt) | 256 | 21 | 231 | 482.11 |   1.89|
| [MetroHash-128.var2](MetroHash-128.var2.txt) | 128 | 22 | 246 |  59.10 |   5.09|
| [CLhash.bitmix](CLhash.bitmix.txt) | 64 | 22 | 246 |  66.69 |   7.34|
| [prvhash-128](prvhash-128.txt) | 128 | 23 | 234 |  82.48 |   0.88|
| [t1ha2-128.incr](t1ha2-128.incr.txt) | 128 | 23 | 246 | 110.10 |   4.86|
| [FARSH-128.tweaked](FARSH-128.tweaked.txt) | 128 | 24 | 234 | 241.10 |   3.94|
| [mum3.exact.unroll1](mum3.exact.unroll1.txt) | 64 | 25 | 246 |  35.57 |   2.62|
| [XXH3-64](XXH3-64.txt) | 64 | 28 | 246 |  36.10 |  12.76|
| [MetroHash-64](MetroHash-64.txt) | 64 | 29 | 246 |  48.41 |   5.02|
| [MetroHash-64.var2](MetroHash-64.var2.txt) | 64 | 29 | 246 |  48.50 |   5.01|
| [prvhash-64](prvhash-64.txt) | 64 | 29 | 234 |  56.56 |   0.92|
| [mum3.exact.unroll2](mum3.exact.unroll2.txt) | 64 | 33 | 246 |  33.21 |   4.97|
| [MetroHash-64.var1](MetroHash-64.var1.txt) | 64 | 33 | 246 |  48.54 |   4.98|
| [tabulation-64](tabulation-64.txt) | 64 | 34 | 246 |  43.29 |   3.08|
| [mum3.exact.unroll3](mum3.exact.unroll3.txt) | 64 | 36 | 246 |  33.43 |   6.11|
| [mum3.exact.unroll4](mum3.exact.unroll4.txt) | 64 | 36 | 246 |  33.51 |   5.84|
| [UMASH-64.reseed](UMASH-64.reseed.txt) | 64 | 36 | 246 |  46.93 |   6.08|
| [mx3.v3](mx3.v3.txt) | 64 | 36 | 246 |  55.41 |   3.76|
| [mx3.v2](mx3.v2.txt) | 64 | 36 | 246 |  57.61 |   3.21|
| [XXH3-128](XXH3-128.txt) | 128 | 36 | 246 |  64.28 |  12.73|
| [HalftimeHash-64](HalftimeHash-64.txt) | 64 | 36 | 246 |  89.95 |   2.02|
| [UMASH-128.reseed](UMASH-128.reseed.txt) | 128 | 37 | 246 |  50.78 |   3.87|
| [FarmHash-64.UO](FarmHash-64.UO.txt) | 64 | 39 | 246 |  57.65 |   5.11|
| [FarmHash-64.TE](FarmHash-64.TE.txt) | 64 | 39 | 246 |  57.93 |   7.77|
| [FarmHash-32.MK](FarmHash-32.MK.txt) | 32 | 42 | 246 |  48.82 |   1.54|
| [mum2.inexact.unroll1](mum2.inexact.unroll1.txt) | 64 | 44 | 246 |  48.77 |   1.14|
| [mum2.exact.unroll1](mum2.exact.unroll1.txt) | 64 | 45 | 246 |  38.60 |   2.59|
| [mx3.v1](mx3.v1.txt) | 64 | 45 | 246 |  55.51 |   3.21|
| [seahash](seahash.txt) | 64 | 45 | 246 |  61.14 |   2.66|
| [MetroHashCrc-64.var1](MetroHashCrc-64.var1.txt) | 64 | 46 | 246 |  52.47 |   7.97|
| [MetroHashCrc-64.var2](MetroHashCrc-64.var2.txt) | 64 | 47 | 246 |  52.48 |   7.87|
| [CityHash-64](CityHash-64.txt) | 64 | 47 | 246 |  57.71 |   4.81|
| [FarmHash-64.NA](FarmHash-64.NA.txt) | 64 | 48 | 246 |  57.60 |   4.68|
| [MetroHashCrc-128.var2](MetroHashCrc-128.var2.txt) | 128 | 49 | 246 |  64.58 |   7.97|
| [MetroHashCrc-128.var1](MetroHashCrc-128.var1.txt) | 128 | 49 | 246 |  64.59 |   7.97|
| [FarmHash-32.SA](FarmHash-32.SA.txt) | 32 | 50 | 246 |  48.80 |   4.99|
| [HalftimeHash-256](HalftimeHash-256.txt) | 64 | 50 | 246 | 104.19 |  11.37|
| [FarmHash-32.SU](FarmHash-32.SU.txt) | 32 | 51 | 246 |  48.84 |   5.99|
| [FarmHash-32.CC](FarmHash-32.CC.txt) | 32 | 51 | 246 |  49.00 |   1.91|
| [HalftimeHash-128](HalftimeHash-128.txt) | 64 | 52 | 246 | 101.23 |   6.79|
| [VHASH.32](VHASH.32.txt) | 32 | 54 | 246 |  97.42 |   5.12|
| [AquaHash](AquaHash.txt) | 128 | 55 | 246 |  40.29 |  15.95|
| [VHASH](VHASH.txt) | 64 | 59 | 246 |  97.42 |   5.12|
| [fasthash-32](fasthash-32.txt) | 32 | 60 | 246 |  47.47 |   2.00|
| [HalftimeHash-512](HalftimeHash-512.txt) | 64 | 60 | 246 | 121.74 |   9.46|
| [mum2.inexact.unroll2](mum2.inexact.unroll2.txt) | 64 | 61 | 246 |  44.34 |   1.26|
| [mum2.exact.unroll2](mum2.exact.unroll2.txt) | 64 | 62 | 246 |  36.75 |   4.26|
| [t1ha1](t1ha1.txt) | 64 | 64 | 246 |  36.96 |   4.57|
| [poly-mersenne.deg3](poly-mersenne.deg3.txt) | 32 | 64 | 234 |  76.62 |   0.50|
| [poly-mersenne.deg4](poly-mersenne.deg4.txt) | 32 | 64 | 234 |  85.95 |   0.50|
| [mum2.exact.unroll3](mum2.exact.unroll3.txt) | 64 | 70 | 246 |  36.74 |   4.34|
| [mum2.inexact.unroll3](mum2.inexact.unroll3.txt) | 64 | 70 | 246 |  44.51 |   1.31|
| [NMHASH](NMHASH.txt) | 32 | 75 | 246 |  58.79 |   7.69|
| [mum2.exact.unroll4](mum2.exact.unroll4.txt) | 64 | 77 | 246 |  36.07 |   3.93|
| [mum2.inexact.unroll4](mum2.inexact.unroll4.txt) | 64 | 77 | 246 |  44.74 |   1.86|
| [poly-mersenne.deg2](poly-mersenne.deg2.txt) | 32 | 80 | 234 |  67.65 |   0.50|
| [PMP-Multilinear-64](PMP-Multilinear-64.txt) | 64 | 82 | 246 |  55.94 |   4.27|
| [MurmurHash3-32](MurmurHash3-32.txt) | 32 | 83 | 246 |  50.88 |   1.00|
| [XXH-32](XXH-32.txt) | 32 | 84 | 246 |  50.55 |   2.00|
| [MurmurHash3-128](MurmurHash3-128.txt) | 128 | 87 | 246 |  53.65 |   2.36|
| [lookup3.32](lookup3.32.txt) | 32 | 90 | 234 |  42.19 |   0.81|
| [CityHash-32](CityHash-32.txt) | 32 | 90 | 246 |  49.98 |   1.90|
| [floppsyhash.old](floppsyhash.old.txt) | 64 | 93 | 231 | 744.88 |   0.04|
| [mum3.inexact.unroll1](mum3.inexact.unroll1.txt) | 64 | 97 | 246 |  44.65 |   1.39|
| [NMHASHX](NMHASHX.txt) | 32 | 98 | 246 |  45.72 |   7.69|
| [Discohash-128.old](Discohash-128.old.txt) | 128 | 98 | 234 | 215.60 |   1.34|
| [fasthash-64](fasthash-64.txt) | 64 | 99 | 246 |  45.75 |   2.00|
| [MurmurHash3-128.int32](MurmurHash3-128.int32.txt) | 128 | 99 | 246 |  52.88 |   1.63|
| [MurmurHash2-64](MurmurHash2-64.txt) | 64 | 100 | 246 |  46.07 |   2.00|
| [Discohash-128](Discohash-128.txt) | 128 | 100 | 234 | 231.75 |   1.34|
| [MurmurHash1](MurmurHash1.txt) | 32 | 114 | 234 |  52.33 |   0.67|
| [mum3.inexact.unroll2](mum3.inexact.unroll2.txt) | 64 | 115 | 246 |  39.83 |   1.81|
| [mum3.inexact.unroll3](mum3.inexact.unroll3.txt) | 64 | 125 | 246 |  40.01 |   2.02|
| [UMASH-64](UMASH-64.txt) | 64 | 126 | 246 |  48.27 |   6.08|
| [UMASH-128](UMASH-128.txt) | 128 | 127 | 246 |  50.72 |   3.87|
| [lookup3](lookup3.txt) | 64 | 129 | 234 |  42.12 |   0.81|
| [mum3.inexact.unroll4](mum3.inexact.unroll4.txt) | 64 | 130 | 246 |  41.13 |   1.98|
| [perl-jenkins-hard](perl-jenkins-hard.txt) | 32 | 134 | 231 | 121.01 |   0.20|
| [MurmurHash2a](MurmurHash2a.txt) | 32 | 147 | 246 |  49.79 |   1.00|
| [tabulation-32](tabulation-32.txt) | 32 | 155 | 246 |  34.07 |   2.20|
| [Crap8](Crap8.txt) | 32 | 158 | 246 |  40.06 |   1.00|
| [perl-jenkins](perl-jenkins.txt) | 32 | 160 | 231 | 101.00 |   0.20|
| [PMP-Multilinear-32](PMP-Multilinear-32.txt) | 32 | 167 | 234 |  46.94 |   0.85|
| [MurmurHash2-32](MurmurHash2-32.txt) | 32 | 171 | 246 |  45.03 |   1.00|
| [MicroOAAT](MicroOAAT.txt) | 32 | 191 | 231 |  82.41 |   0.24|
| [CLhash](CLhash.txt) | 64 | 194 | 246 |  50.93 |   7.33|
| [poly-mersenne.deg1](poly-mersenne.deg1.txt) | 32 | 194 | 234 |  59.34 |   0.50|
| [MurmurHash2-64.int32](MurmurHash2-64.int32.txt) | 64 | 203 | 246 |  50.66 |   1.33|
| [jodyhash-32](jodyhash-32.txt) | 32 | 216 | 234 |  46.09 |   0.57|
| [SuperFastHash](SuperFastHash.txt) | 32 | 217 | 234 |  51.14 |   0.78|
| [Pearson-256](Pearson-256.txt) | 256 | 217 | 231 | 132.38 |   0.14|
| [Pearson-128](Pearson-128.txt) | 128 | 218 | 231 | 127.02 |   0.14|
| [Pearson-64](Pearson-64.txt) | 64 | 218 | 231 | 131.08 |   0.14|
| [pair-multiply-shift-32](pair-multiply-shift-32.txt) | 32 | 221 | 246 |  29.06 |   2.21|
| [FNV-1a-32](FNV-1a-32.txt) | 32 | 224 | 231 |  79.01 |   0.25|
| [pair-multiply-shift](pair-multiply-shift.txt) | 64 | 225 | 246 |  31.72 |   1.87|
| [multiply-shift-32](multiply-shift-32.txt) | 32 | 226 | 246 |  24.76 |   1.51|
| [multiply-shift](multiply-shift.txt) | 64 | 226 | 246 |  30.72 |   1.75|
| [perl-djb2](perl-djb2.txt) | 32 | 226 | 231 |  61.02 |   0.33|
| [perl-sdbm](perl-sdbm.txt) | 32 | 226 | 231 |  76.02 |   0.25|
| [FNV-1a-64](FNV-1a-64.txt) | 64 | 226 | 231 |  79.00 |   0.25|
| [x17](x17.txt) | 32 | 226 | 231 |  79.07 |   0.25|
| [FNV-YoshimitsuTRIAD](FNV-YoshimitsuTRIAD.txt) | 32 | 227 | 246 |  32.18 |   5.26|
| [CRC-32C](CRC-32C.txt) | 32 | 231 | 246 |  36.78 |   7.63|
| [Fletcher-32](Fletcher-32.txt) | 32 | 235 | 246 |  39.05 |   1.40|
| [Fletcher-64](Fletcher-64.txt) | 64 | 238 | 246 |  39.27 |   2.84|


Hashes that pass Sanity tests, but fail others, sorted by average short input speed and then failing tests.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [multiply-shift-32](multiply-shift-32.txt) | 32 | 226 | 246 |  24.76 |   1.51|
| [pair-multiply-shift-32](pair-multiply-shift-32.txt) | 32 | 221 | 246 |  29.06 |   2.21|
| [multiply-shift](multiply-shift.txt) | 64 | 226 | 246 |  30.72 |   1.75|
| [pair-multiply-shift](pair-multiply-shift.txt) | 64 | 225 | 246 |  31.72 |   1.87|
| [FNV-YoshimitsuTRIAD](FNV-YoshimitsuTRIAD.txt) | 32 | 227 | 246 |  32.18 |   5.26|
| [mum3.exact.unroll2](mum3.exact.unroll2.txt) | 64 | 33 | 246 |  33.21 |   4.97|
| [mum3.exact.unroll3](mum3.exact.unroll3.txt) | 64 | 36 | 246 |  33.43 |   6.11|
| [mum3.exact.unroll4](mum3.exact.unroll4.txt) | 64 | 36 | 246 |  33.51 |   5.84|
| [tabulation-32](tabulation-32.txt) | 32 | 155 | 246 |  34.07 |   2.20|
| [wyhash](wyhash.txt) | 64 | 11 | 246 |  35.31 |   6.97|
| [mum3.exact.unroll1](mum3.exact.unroll1.txt) | 64 | 25 | 246 |  35.57 |   2.62|
| [mum2.exact.unroll4](mum2.exact.unroll4.txt) | 64 | 77 | 246 |  36.07 |   3.93|
| [XXH3-64](XXH3-64.txt) | 64 | 28 | 246 |  36.10 |  12.76|
| [XXH3-64.regen](XXH3-64.regen.txt) | 64 | 15 | 246 |  36.23 |  12.76|
| [mum2.exact.unroll3](mum2.exact.unroll3.txt) | 64 | 70 | 246 |  36.74 |   4.34|
| [mum2.exact.unroll2](mum2.exact.unroll2.txt) | 64 | 62 | 246 |  36.75 |   4.26|
| [CRC-32C](CRC-32C.txt) | 32 | 231 | 246 |  36.78 |   7.63|
| [t1ha1](t1ha1.txt) | 64 | 64 | 246 |  36.96 |   4.57|
| [wyhash-32](wyhash-32.txt) | 32 | 2 | 246 |  37.00 |   1.33|
| [wyhash.strict](wyhash.strict.txt) | 64 | 11 | 246 |  37.12 |   5.77|
| [mum2.exact.unroll1](mum2.exact.unroll1.txt) | 64 | 45 | 246 |  38.60 |   2.59|
| [Fletcher-32](Fletcher-32.txt) | 32 | 235 | 246 |  39.05 |   1.40|
| [Fletcher-64](Fletcher-64.txt) | 64 | 238 | 246 |  39.27 |   2.84|
| [mum3.inexact.unroll2](mum3.inexact.unroll2.txt) | 64 | 115 | 246 |  39.83 |   1.81|
| [mum3.inexact.unroll3](mum3.inexact.unroll3.txt) | 64 | 125 | 246 |  40.01 |   2.02|
| [Crap8](Crap8.txt) | 32 | 158 | 246 |  40.06 |   1.00|
| [mum1.exact.unroll4](mum1.exact.unroll4.txt) | 64 | 18 | 246 |  40.22 |   3.93|
| [AquaHash](AquaHash.txt) | 128 | 55 | 246 |  40.29 |  15.95|
| [mum1.exact.unroll3](mum1.exact.unroll3.txt) | 64 | 18 | 246 |  40.54 |   4.34|
| [mum1.exact.unroll2](mum1.exact.unroll2.txt) | 64 | 18 | 246 |  40.58 |   4.25|
| [mum3.inexact.unroll4](mum3.inexact.unroll4.txt) | 64 | 130 | 246 |  41.13 |   1.98|
| [lookup3](lookup3.txt) | 64 | 129 | 234 |  42.12 |   0.81|
| [lookup3.32](lookup3.32.txt) | 32 | 90 | 234 |  42.19 |   0.81|
| [mum1.exact.unroll1](mum1.exact.unroll1.txt) | 64 | 18 | 246 |  42.57 |   2.58|
| [tabulation-64](tabulation-64.txt) | 64 | 34 | 246 |  43.29 |   3.08|
| [mir.exact](mir.exact.txt) | 64 | 18 | 246 |  43.89 |   2.13|
| [mum2.inexact.unroll2](mum2.inexact.unroll2.txt) | 64 | 61 | 246 |  44.34 |   1.26|
| [mum2.inexact.unroll3](mum2.inexact.unroll3.txt) | 64 | 70 | 246 |  44.51 |   1.31|
| [mum3.inexact.unroll1](mum3.inexact.unroll1.txt) | 64 | 97 | 246 |  44.65 |   1.39|
| [mum2.inexact.unroll4](mum2.inexact.unroll4.txt) | 64 | 77 | 246 |  44.74 |   1.86|
| [MurmurHash2-32](MurmurHash2-32.txt) | 32 | 171 | 246 |  45.03 |   1.00|
| [NMHASHX](NMHASHX.txt) | 32 | 98 | 246 |  45.72 |   7.69|
| [fasthash-64](fasthash-64.txt) | 64 | 99 | 246 |  45.75 |   2.00|
| [MurmurHash2-64](MurmurHash2-64.txt) | 64 | 100 | 246 |  46.07 |   2.00|
| [jodyhash-32](jodyhash-32.txt) | 32 | 216 | 234 |  46.09 |   0.57|
| [UMASH-64.reseed](UMASH-64.reseed.txt) | 64 | 36 | 246 |  46.93 |   6.08|
| [PMP-Multilinear-32](PMP-Multilinear-32.txt) | 32 | 167 | 234 |  46.94 |   0.85|
| [t1ha0.aesA](t1ha0.aesA.txt) | 64 | 5 | 246 |  47.09 |   9.09|
| [t1ha2-64](t1ha2-64.txt) | 64 | 3 | 246 |  47.13 |   4.62|
| [t1ha0.aesB](t1ha0.aesB.txt) | 64 | 5 | 246 |  47.25 |  21.35|
| [fasthash-32](fasthash-32.txt) | 32 | 60 | 246 |  47.47 |   2.00|
| [TinySipHash](TinySipHash.txt) | 64 | 13 | 246 |  47.75 |   1.50|
| [UMASH-64](UMASH-64.txt) | 64 | 126 | 246 |  48.27 |   6.08|
| [MetroHash-64](MetroHash-64.txt) | 64 | 29 | 246 |  48.41 |   5.02|
| [MetroHash-64.var2](MetroHash-64.var2.txt) | 64 | 29 | 246 |  48.50 |   5.01|
| [MetroHash-64.var1](MetroHash-64.var1.txt) | 64 | 33 | 246 |  48.54 |   4.98|
| [mum2.inexact.unroll1](mum2.inexact.unroll1.txt) | 64 | 44 | 246 |  48.77 |   1.14|
| [FarmHash-32.SA](FarmHash-32.SA.txt) | 32 | 50 | 246 |  48.80 |   4.99|
| [FarmHash-32.MK](FarmHash-32.MK.txt) | 32 | 42 | 246 |  48.82 |   1.54|
| [FarmHash-32.SU](FarmHash-32.SU.txt) | 32 | 51 | 246 |  48.84 |   5.99|
| [FarmHash-32.CC](FarmHash-32.CC.txt) | 32 | 51 | 246 |  49.00 |   1.91|
| [MurmurHash2a](MurmurHash2a.txt) | 32 | 147 | 246 |  49.79 |   1.00|
| [CityHash-32](CityHash-32.txt) | 32 | 90 | 246 |  49.98 |   1.90|
| [XXH-32](XXH-32.txt) | 32 | 84 | 246 |  50.55 |   2.00|
| [MurmurHash2-64.int32](MurmurHash2-64.int32.txt) | 64 | 203 | 246 |  50.66 |   1.33|
| [UMASH-128](UMASH-128.txt) | 128 | 127 | 246 |  50.72 |   3.87|
| [UMASH-128.reseed](UMASH-128.reseed.txt) | 128 | 37 | 246 |  50.78 |   3.87|
| [MurmurHash3-32](MurmurHash3-32.txt) | 32 | 83 | 246 |  50.88 |   1.00|
| [CLhash](CLhash.txt) | 64 | 194 | 246 |  50.93 |   7.33|
| [SuperFastHash](SuperFastHash.txt) | 32 | 217 | 234 |  51.14 |   0.78|
| [t1ha0](t1ha0.txt) | 64 | 18 | 246 |  51.38 |   2.42|
| [MurmurHash1](MurmurHash1.txt) | 32 | 114 | 234 |  52.33 |   0.67|
| [MetroHashCrc-64.var1](MetroHashCrc-64.var1.txt) | 64 | 46 | 246 |  52.47 |   7.97|
| [MetroHashCrc-64.var2](MetroHashCrc-64.var2.txt) | 64 | 47 | 246 |  52.48 |   7.87|
| [mum1.inexact.unroll2](mum1.inexact.unroll2.txt) | 64 | 16 | 246 |  52.58 |   1.20|
| [MurmurHash3-128.int32](MurmurHash3-128.int32.txt) | 128 | 99 | 246 |  52.88 |   1.63|
| [mum1.inexact.unroll3](mum1.inexact.unroll3.txt) | 64 | 17 | 246 |  52.95 |   1.31|
| [mum1.inexact.unroll4](mum1.inexact.unroll4.txt) | 64 | 17 | 246 |  53.05 |   1.86|
| [MurmurHash3-128](MurmurHash3-128.txt) | 128 | 87 | 246 |  53.65 |   2.36|
| [mir.inexact](mir.inexact.txt) | 64 | 17 | 246 |  54.62 |   1.33|
| [mx3.v3](mx3.v3.txt) | 64 | 36 | 246 |  55.41 |   3.76|
| [mx3.v1](mx3.v1.txt) | 64 | 45 | 246 |  55.51 |   3.21|
| [PMP-Multilinear-64](PMP-Multilinear-64.txt) | 64 | 82 | 246 |  55.94 |   4.27|
| [mum1.inexact.unroll1](mum1.inexact.unroll1.txt) | 64 | 17 | 246 |  56.40 |   1.14|
| [prvhash-64](prvhash-64.txt) | 64 | 29 | 234 |  56.56 |   0.92|
| [FarmHash-64.NA](FarmHash-64.NA.txt) | 64 | 48 | 246 |  57.60 |   4.68|
| [mx3.v2](mx3.v2.txt) | 64 | 36 | 246 |  57.61 |   3.21|
| [FarmHash-64.UO](FarmHash-64.UO.txt) | 64 | 39 | 246 |  57.65 |   5.11|
| [CityHash-64](CityHash-64.txt) | 64 | 47 | 246 |  57.71 |   4.81|
| [FarmHash-32.NT](FarmHash-32.NT.txt) | 32 | 7 | 246 |  57.82 |   7.78|
| [FarmHash-64.TE](FarmHash-64.TE.txt) | 64 | 39 | 246 |  57.93 |   7.77|
| [XXH-64](XXH-64.txt) | 64 | 9 | 246 |  58.73 |   3.99|
| [NMHASH](NMHASH.txt) | 32 | 75 | 246 |  58.79 |   7.69|
| [MetroHash-128](MetroHash-128.txt) | 128 | 17 | 246 |  59.09 |   5.09|
| [MetroHash-128.var1](MetroHash-128.var1.txt) | 128 | 20 | 246 |  59.10 |   5.08|
| [MetroHash-128.var2](MetroHash-128.var2.txt) | 128 | 22 | 246 |  59.10 |   5.09|
| [poly-mersenne.deg1](poly-mersenne.deg1.txt) | 32 | 194 | 234 |  59.34 |   0.50|
| [khashv-64](khashv-64.txt) | 64 | 5 | 246 |  59.44 |   2.97|
| [perl-djb2](perl-djb2.txt) | 32 | 226 | 231 |  61.02 |   0.33|
| [seahash](seahash.txt) | 64 | 45 | 246 |  61.14 |   2.66|
| [XXH3-128](XXH3-128.txt) | 128 | 36 | 246 |  64.28 |  12.73|
| [XXH3-128.regen](XXH3-128.regen.txt) | 128 | 16 | 246 |  64.31 |  12.68|
| [MetroHashCrc-128.var2](MetroHashCrc-128.var2.txt) | 128 | 49 | 246 |  64.58 |   7.97|
| [MetroHashCrc-128.var1](MetroHashCrc-128.var1.txt) | 128 | 49 | 246 |  64.59 |   7.97|
| [SpookyHash1-64](SpookyHash1-64.txt) | 64 | 5 | 246 |  64.85 |   4.40|
| [SpookyHash2-64](SpookyHash2-64.txt) | 64 | 3 | 246 |  66.29 |   4.40|
| [CLhash.bitmix](CLhash.bitmix.txt) | 64 | 22 | 246 |  66.69 |   7.34|
| [poly-mersenne.deg2](poly-mersenne.deg2.txt) | 32 | 80 | 234 |  67.65 |   0.50|
| [t1ha2-128](t1ha2-128.txt) | 128 | 1 | 246 |  67.84 |   4.89|
| [SpookyHash1-128](SpookyHash1-128.txt) | 128 | 14 | 246 |  69.29 |   4.40|
| [FARSH-32.tweaked](FARSH-32.tweaked.txt) | 32 | 19 | 246 |  69.96 |  16.02|
| [SpookyHash2-128](SpookyHash2-128.txt) | 128 | 13 | 246 |  70.56 |   4.40|
| [FarmHash-128.CC.seed1](FarmHash-128.CC.seed1.txt) | 128 | 2 | 246 |  74.26 |   4.84|
| [FarmHash-128.CC.seed2](FarmHash-128.CC.seed2.txt) | 128 | 10 | 246 |  74.27 |   4.82|
| [CityHash-128.seed1](CityHash-128.seed1.txt) | 128 | 2 | 246 |  74.43 |   4.84|
| [CityHash-128.seed3](CityHash-128.seed3.txt) | 128 | 2 | 246 |  74.48 |   4.85|
| [FarmHash-128.CM.seed2](FarmHash-128.CM.seed2.txt) | 128 | 8 | 246 |  74.65 |   2.61|
| [CityHash-128.seed2](CityHash-128.seed2.txt) | 128 | 10 | 246 |  74.65 |   4.84|
| [CityMurmur.seed2](CityMurmur.seed2.txt) | 128 | 8 | 246 |  74.68 |   2.61|
| [CityHashCrc-128.seed1](CityHashCrc-128.seed1.txt) | 128 | 7 | 246 |  74.75 |   5.30|
| [CityHashCrc-128.seed3](CityHashCrc-128.seed3.txt) | 128 | 7 | 246 |  74.78 |   5.31|
| [CityHashCrc-128.seed2](CityHashCrc-128.seed2.txt) | 128 | 14 | 246 |  74.79 |   5.31|
| [FarmHash-128.CC.seed3](FarmHash-128.CC.seed3.txt) | 128 | 2 | 246 |  75.91 |   4.84|
| [perl-sdbm](perl-sdbm.txt) | 32 | 226 | 231 |  76.02 |   0.25|
| [poly-mersenne.deg3](poly-mersenne.deg3.txt) | 32 | 64 | 234 |  76.62 |   0.50|
| [pengyhash](pengyhash.txt) | 64 | 5 | 246 |  76.64 |   4.62|
| [FNV-1a-64](FNV-1a-64.txt) | 64 | 226 | 231 |  79.00 |   0.25|
| [FNV-1a-32](FNV-1a-32.txt) | 32 | 224 | 231 |  79.01 |   0.25|
| [x17](x17.txt) | 32 | 226 | 231 |  79.07 |   0.25|
| [MicroOAAT](MicroOAAT.txt) | 32 | 191 | 231 |  82.41 |   0.24|
| [prvhash-128](prvhash-128.txt) | 128 | 23 | 234 |  82.48 |   0.88|
| [t1ha2-64.incr](t1ha2-64.incr.txt) | 64 | 18 | 246 |  85.48 |   4.86|
| [poly-mersenne.deg4](poly-mersenne.deg4.txt) | 32 | 64 | 234 |  85.95 |   0.50|
| [falkhash1](falkhash1.txt) | 128 | 10 | 246 |  89.89 |  19.82|
| [HalftimeHash-64](HalftimeHash-64.txt) | 64 | 36 | 246 |  89.95 |   2.02|
| [falkhash2](falkhash2.txt) | 128 | 6 | 246 |  91.90 |  18.40|
| [VHASH.32](VHASH.32.txt) | 32 | 54 | 246 |  97.42 |   5.12|
| [VHASH](VHASH.txt) | 64 | 59 | 246 |  97.42 |   5.12|
| [perl-jenkins](perl-jenkins.txt) | 32 | 160 | 231 | 101.00 |   0.20|
| [HalftimeHash-128](HalftimeHash-128.txt) | 64 | 52 | 246 | 101.23 |   6.79|
| [HalftimeHash-256](HalftimeHash-256.txt) | 64 | 50 | 246 | 104.19 |  11.37|
| [t1ha2-128.incr](t1ha2-128.incr.txt) | 128 | 23 | 246 | 110.10 |   4.86|
| [perl-jenkins-hard](perl-jenkins-hard.txt) | 32 | 134 | 231 | 121.01 |   0.20|
| [HalftimeHash-512](HalftimeHash-512.txt) | 64 | 60 | 246 | 121.74 |   9.46|
| [FARSH-64.tweaked](FARSH-64.tweaked.txt) | 64 | 20 | 246 | 122.28 |   7.87|
| [Pearson-128](Pearson-128.txt) | 128 | 218 | 231 | 127.02 |   0.14|
| [Pearson-64](Pearson-64.txt) | 64 | 218 | 231 | 131.08 |   0.14|
| [Pearson-256](Pearson-256.txt) | 256 | 217 | 231 | 132.38 |   0.14|
| [Discohash-128.old](Discohash-128.old.txt) | 128 | 98 | 234 | 215.60 |   1.34|
| [Discohash-128](Discohash-128.txt) | 128 | 100 | 234 | 231.75 |   1.34|
| [Discohash](Discohash.txt) | 64 | 21 | 234 | 233.56 |   1.34|
| [FARSH-128.tweaked](FARSH-128.tweaked.txt) | 128 | 24 | 234 | 241.10 |   3.94|
| [FARSH-256.tweaked](FARSH-256.tweaked.txt) | 256 | 21 | 231 | 482.11 |   1.89|
| [floppsyhash](floppsyhash.txt) | 64 | 16 | 231 | 739.99 |   0.05|
| [floppsyhash.old](floppsyhash.old.txt) | 64 | 93 | 231 | 744.88 |   0.04|
| [beamsplitter](beamsplitter.txt) | 64 | 4 | 231 | 924.46 |   0.18|

Unusable hashes
---------------

Hashes that fail Sanity tests, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [aesrng-32](aesrng-32.txt) | 32 | 2 | 246 |  73.00 | 2545.07|
| [aesrng-64](aesrng-64.txt) | 64 | 2 | 246 |  73.00 | 2544.91|
| [aesrng-128](aesrng-128.txt) | 128 | 2 | 246 |  86.52 | 2138.61|
| [aesrng-160](aesrng-160.txt) | 160 | 2 | 246 | 108.94 | 1861.73|
| [aesrng-224](aesrng-224.txt) | 224 | 2 | 246 | 155.00 | 1369.81|
| [aesrng-256](aesrng-256.txt) | 256 | 2 | 246 | 155.00 | 1368.08|
| [FARSH-32](FARSH-32.txt) | 32 | 28 | 246 |  70.48 |  14.11|
| [hasshe2](hasshe2.txt) | 256 | 29 | 234 | 102.94 |   0.92|
| [FARSH-256](FARSH-256.txt) | 256 | 29 | 231 | 486.19 |   1.75|
| [FARSH-64](FARSH-64.txt) | 64 | 30 | 246 | 122.73 |   6.98|
| [FARSH-128](FARSH-128.txt) | 128 | 34 | 234 | 242.60 |   3.50|
| [XXH3-64.reinit](XXH3-64.reinit.txt) | 64 | 52 | 246 |  36.22 |  12.69|
| [XXH3-128.reinit](XXH3-128.reinit.txt) | 128 | 53 | 246 |  64.30 |  12.74|
| [aesnihash](aesnihash.txt) | 64 | 64 | 246 |  64.05 |   1.78|
| [CrapWow-64](CrapWow-64.txt) | 64 | 137 | 246 |  36.80 |   4.84|
| [khash-64](khash-64.txt) | 64 | 141 | 246 |  47.92 |   1.56|
| [MurmurOAAT](MurmurOAAT.txt) | 32 | 162 | 231 | 111.00 |   0.17|
| [CrapWow](CrapWow.txt) | 32 | 164 | 246 |  31.21 |   2.58|
| [perl-jenkins-old](perl-jenkins-old.txt) | 32 | 170 | 231 | 101.00 |   0.20|
| [khash-32](khash-32.txt) | 32 | 179 | 246 |  59.04 |   1.39|
| [FNV-PippipYurii](FNV-PippipYurii.txt) | 32 | 193 | 246 |  37.60 |   2.00|
| [FNV-Totenschiff](FNV-Totenschiff.txt) | 32 | 202 | 246 |  36.06 |   2.00|
| [badhash](badhash.txt) | 32 | 222 | 231 |  80.84 |   0.24|
| [jodyhash-64](jodyhash-64.txt) | 64 | 227 | 246 |  39.00 |   1.14|
| [FNV-1a-64.wordwise](FNV-1a-64.wordwise.txt) | 64 | 236 | 246 |  40.86 |   2.00|
| [FNV-1a-32.wordwise](FNV-1a-32.wordwise.txt) | 32 | 238 | 246 |  35.68 |   1.00|
| [fletcher2.64](fletcher2.64.txt) | 64 | 240 | 246 |  27.26 |   4.93|
| [fletcher2](fletcher2.txt) | 128 | 240 | 246 |  30.10 |   4.92|
| [fibonacci-64](fibonacci-64.txt) | 64 | 242 | 246 |  28.55 |   9.51|
| [sum32hash](sum32hash.txt) | 32 | 243 | 246 |  20.56 |  26.64|
| [fibonacci-32](fibonacci-32.txt) | 32 | 243 | 246 |  30.96 |  15.94|
| [fletcher4](fletcher4.txt) | 256 | 243 | 246 |  34.16 |   1.91|
| [sum8hash](sum8hash.txt) | 32 | 243 | 246 |  35.65 |   3.35|
| [o1hash](o1hash.txt) | 64 | 244 | 246 |  20.95 | 7470.65|
| [fletcher4.64](fletcher4.64.txt) | 64 | 244 | 246 |  27.14 |   1.91|
| [donothing-128](donothing-128.txt) | 128 | 245 | 246 |   5.00 | 7486.64|
| [donothing-256](donothing-256.txt) | 256 | 245 | 246 |   5.00 | 7486.52|
| [donothing-32](donothing-32.txt) | 32 | 245 | 246 |   5.00 | 7486.53|
| [donothing-64](donothing-64.txt) | 64 | 245 | 246 |   5.00 | 7487.48|
| [donothingOAAT-64](donothingOAAT-64.txt) | 64 | 245 | 246 |  44.81 |   3.39|
| [donothingOAAT-32](donothingOAAT-32.txt) | 32 | 245 | 246 |  45.23 |   3.39|
| [donothingOAAT-128](donothingOAAT-128.txt) | 128 | 245 | 246 |  45.24 |   3.39|

All results were generated using: SMHasher3 beta2-1c3798dc

[\*\*]: this result had >= 1% std. deviation in >=25% of tests, and so may not be reliable
