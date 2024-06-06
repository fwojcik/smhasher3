SMHasher3 results summary
=========================

[[_TOC_]]

Passing hashes
--------------

Hashes that currently pass all tests, sorted by average short input speed.

| Hash name | output width | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-----------:|-------------------------:|------------------------:|
| [rapidhash](raw/rapidhash.txt) | 64 | 250 |  35.37 |   7.25|
| [rust-ahash-fb](raw/rust-ahash-fb.txt) | 64 | 250 |  35.49 |   4.51|
| [rust-ahash-fb.nofold](raw/rust-ahash-fb.nofold.txt) | 64 | 250 |  37.37 |   3.45|
| [rapidhash.protected](raw/rapidhash.protected.txt) | 64 | 250 |  37.50 |   5.65|
| [komihash](raw/komihash.txt) | 64 | 250 |  38.09 |   6.45|
| [polymurhash](raw/polymurhash.txt) | 64 | 250 |  48.42 |   4.02|
| [khashv-64](raw/khashv-64.txt) | 64 | 250 |  62.17 |   3.20|
| [khashv-32](raw/khashv-32.txt) | 32 | 250 |  63.19 |   3.20|
| [SpookyHash1-32](raw/SpookyHash1-32.txt) | 32 | 250 |  64.83 |   4.40|
| [SpookyHash2-32](raw/SpookyHash2-32.txt) | 32 | 250 |  66.26 |   4.40|
| [MeowHash.32](raw/MeowHash.32.txt) | 32 | 250 |  67.50 |  12.38|
| [MeowHash.64](raw/MeowHash.64.txt) | 64 | 250 |  67.50 |  12.24|
| [rainbow](raw/rainbow.txt) | 64 | 250 |  73.87 |   1.78|
| [rainbow-128](raw/rainbow-128.txt) | 128 | 250 |  74.00 |   1.78|
| [FarmHash-128.CM.seed1](raw/FarmHash-128.CM.seed1.txt) | 128 | 250 |  74.66 |   2.61|
| [FarmHash-128.CM.seed3](raw/FarmHash-128.CM.seed3.txt) | 128 | 250 |  75.51 |   2.61|
| [poly-mersenne.deg3](raw/poly-mersenne.deg3.txt) | 32 | 240 |  75.75 |   0.50|
| [HighwayHash-64](raw/HighwayHash-64.txt) | 64 | 238 |  79.48 |   2.89|
| [poly-mersenne.deg4](raw/poly-mersenne.deg4.txt) | 32 | 240 |  83.95 |   0.50|
| [HalfSipHash](raw/HalfSipHash.txt) | 32 | 238 |  88.42 |   0.36|
| [GoodOAAT](raw/GoodOAAT.txt) | 32 | 235 |  92.41 |   0.24|
| [rainbow-256](raw/rainbow-256.txt) | 256 | 250 |  95.21 |   1.78|
| [chaskey-8.32](raw/chaskey-8.32.txt) | 32 | 238 |  99.58 |   0.37|
| [chaskey-8.64](raw/chaskey-8.64.txt) | 64 | 238 | 101.01 |   0.37|
| [hasshe2.tweaked](raw/hasshe2.tweaked.txt) | 256 | 238 | 103.96 |   0.91|
| [HighwayHash-128](raw/HighwayHash-128.txt) | 128 | 238 | 105.17 |   2.92|
| [PearsonBlock-64](raw/PearsonBlock-64.txt) | 64 | 238 | 107.21 |   0.57|
| [chaskey-8](raw/chaskey-8.txt) | 128 | 238 | 107.71 |   0.37|
| [PearsonBlock-128](raw/PearsonBlock-128.txt) | 128 | 238 | 115.38 |   0.53|
| [SipHash-1-3](raw/SipHash-1-3.txt) | 64 | 238 | 116.02 |   0.61|
| [SipHash-1-3.folded](raw/SipHash-1-3.folded.txt) | 32 | 238 | 117.35 |   0.61|
| [chaskey-12.32](raw/chaskey-12.32.txt) | 32 | 235 | 129.64 |   0.25|
| [chaskey-12.64](raw/chaskey-12.64.txt) | 64 | 235 | 131.49 |   0.25|
| [SipHash-2-4](raw/SipHash-2-4.txt) | 64 | 235 | 158.26 |   0.32|
| [HighwayHash-256](raw/HighwayHash-256.txt) | 256 | 238 | 159.28 |   2.83|
| [SipHash-2-4.folded](raw/SipHash-2-4.folded.txt) | 32 | 235 | 159.99 |   0.32|
| [PearsonBlock-256](raw/PearsonBlock-256.txt) | 256 | 238 | 174.73 |   0.33|
| [rainstorm](raw/rainstorm.txt) | 64 | 238 | 190.23 |   0.58|
| [prvhash-64.incr](raw/prvhash-64.incr.txt) | 64 | 238 | 193.26 |   2.29|
| [rainstorm-128](raw/rainstorm-128.txt) | 128 | 238 | 201.02 |   0.58|
| [Discohash1](raw/Discohash1.txt) | 64 | 238 | 213.94 |   1.34|
| [Discohash2](raw/Discohash2.txt) | 64 | 238 | 219.69 |   1.34|
| [Discohash1-128](raw/Discohash1-128.txt) | 128 | 238 | 246.35 |   1.34|
| [Discohash2-128](raw/Discohash2-128.txt) | 128 | 238 | 247.15 |   1.34|
| [rainstorm-256](raw/rainstorm-256.txt) | 256 | 238 | 247.32 |   0.59|
| [prvhash-128.incr](raw/prvhash-128.incr.txt) | 128 | 238 | 285.62 |   2.16|
| [blake3](raw/blake3.txt) | 256 | 235 | 321.65 |   0.42|
| [SHA-2-224](raw/SHA-2-224.txt) | 224 | 235 | 332.47 |   0.45|
| [ascon-XOFa-32](raw/ascon-XOFa-32.txt) | 32 | 235 | 394.36 |   0.08|
| [ascon-XOFa-64](raw/ascon-XOFa-64.txt) | 64 | 235 | 394.93 |   0.08|
| [SHA-2-224.64](raw/SHA-2-224.64.txt) | 64 | 235 | 412.30 |   0.45|
| [SHA-2-256.64](raw/SHA-2-256.64.txt) | 64 | 235 | 412.30 |   0.45|
| [SHA-2-256](raw/SHA-2-256.txt) | 256 | 235 | 431.61 |   0.45|
| [blake2s-256.64](raw/blake2s-256.64.txt) | 64 | 235 | 433.77 |   0.18|
| [blake2s-160](raw/blake2s-160.txt) | 160 | 235 | 435.67 |   0.18|
| [blake2s-256](raw/blake2s-256.txt) | 256 | 235 | 435.77 |   0.18|
| [blake2s-128](raw/blake2s-128.txt) | 128 | 235 | 436.50 |   0.18|
| [blake2s-224](raw/blake2s-224.txt) | 224 | 235 | 446.41 |   0.18|
| [ascon-XOF-32](raw/ascon-XOF-32.txt) | 32 | 235 | 483.14 |   0.05|
| [ascon-XOF-64](raw/ascon-XOF-64.txt) | 64 | 235 | 484.87 |   0.05|
| [RIPEMD-128](raw/RIPEMD-128.txt) | 128 | 235 | 487.46 |   0.15|
| [SHA-1.32](raw/SHA-1.32.txt) | 32 | 235 | 498.07 |   0.48|
| [SHA-1.64](raw/SHA-1.64.txt) | 64 | 235 | 499.23 |   0.48|
| [SHA-1](raw/SHA-1.txt) | 128 | 235 | 500.39 |   0.48|
| [ascon-XOFa-128](raw/ascon-XOFa-128.txt) | 128 | 235 | 502.01 |   0.08|
| [MD5](raw/MD5.txt) | 128 | 235 | 526.42 |   0.14|
| [MD5.32](raw/MD5.32.txt) | 32 | 235 | 526.64 |   0.14|
| [MD5.64](raw/MD5.64.txt) | 64 | 235 | 526.68 |   0.14|
| [RIPEMD-256](raw/RIPEMD-256.txt) | 256 | 235 | 569.61 |   0.13|
| [blake2b-256](raw/blake2b-256.txt) | 256 | 235 | 586.20 |   0.26|
| [blake2b-160](raw/blake2b-160.txt) | 160 | 235 | 586.25 |   0.26|
| [blake2b-256.64](raw/blake2b-256.64.txt) | 64 | 235 | 587.87 |   0.26|
| [blake2b-128](raw/blake2b-128.txt) | 128 | 235 | 593.97 |   0.26|
| [blake2b-224](raw/blake2b-224.txt) | 224 | 235 | 594.33 |   0.26|
| [ascon-XOFa-160](raw/ascon-XOFa-160.txt) | 160 | 235 | 624.88 |   0.08|
| [ascon-XOF-128](raw/ascon-XOF-128.txt) | 128 | 235 | 642.62 |   0.05|
| [RIPEMD-160](raw/RIPEMD-160.txt) | 160 | 235 | 718.20 |   0.10|
| [ascon-XOFa-224](raw/ascon-XOFa-224.txt) | 224 | 235 | 740.04 |   0.08|
| [ascon-XOFa-256](raw/ascon-XOFa-256.txt) | 256 | 235 | 740.15 |   0.08|
| [ascon-XOF-160](raw/ascon-XOF-160.txt) | 160 | 235 | 812.33 |   0.05|
| [ascon-XOF-256](raw/ascon-XOF-256.txt) | 256 | 235 | 982.31 |   0.05|
| [ascon-XOF-224](raw/ascon-XOF-224.txt) | 224 | 235 | 982.47 |   0.05|
| [SHA-3-256.64](raw/SHA-3-256.64.txt) | 64 | 235 | 2968.85 |   0.05|
| [SHA-3](raw/SHA-3.txt) | 256 | 235 | 2970.99 |   0.05|


Failing hashes
--------------

Hashes that pass Sanity tests, but fail others, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [t1ha2-128](raw/t1ha2-128.txt) | 128 | 1 | 250 |  67.34 |   4.89|
| [MeowHash](raw/MeowHash.txt) | 128 | 1 | 250 |  67.50 |  12.17|
| [chaskey-12](raw/chaskey-12.txt) | 128 | 1 | 235 | 138.37 |   0.25|
| [wyhash-32](raw/wyhash-32.txt) | 32 | 2 | 250 |  37.00 |   1.33|
| [FarmHash-128.CC.seed1](raw/FarmHash-128.CC.seed1.txt) | 128 | 2 | 250 |  74.40 |   4.84|
| [FarmHash-128.CC.seed3](raw/FarmHash-128.CC.seed3.txt) | 128 | 2 | 250 |  75.92 |   4.85|
| [t1ha2-64](raw/t1ha2-64.txt) | 64 | 3 | 250 |  46.56 |   4.62|
| [SpookyHash1-64](raw/SpookyHash1-64.txt) | 64 | 4 | 250 |  64.82 |   4.40|
| [beamsplitter](raw/beamsplitter.txt) | 64 | 4 | 235 | 924.27 |   0.18|
| [t1ha0.aesA](raw/t1ha0.aesA.txt) | 64 | 5 | 250 |  46.19 |   9.10|
| [t1ha0.aesB](raw/t1ha0.aesB.txt) | 64 | 5 | 250 |  46.49 |  21.29|
| [SpookyHash2-64](raw/SpookyHash2-64.txt) | 64 | 7 | 250 |  66.26 |   4.40|
| [CityHashCrc-128.seed3](raw/CityHashCrc-128.seed3.txt) | 128 | 7 | 250 |  75.10 |   5.98|
| [CityHashCrc-128.seed1](raw/CityHashCrc-128.seed1.txt) | 128 | 7 | 250 |  75.12 |   6.00|
| [falkhash2](raw/falkhash2.txt) | 128 | 7 | 250 |  91.89 |  17.98|
| [FarmHash-128.CM.seed2](raw/FarmHash-128.CM.seed2.txt) | 128 | 8 | 250 |  74.60 |   2.61|
| [polymurhash-tweakseed](raw/polymurhash-tweakseed.txt) | 64 | 9 | 250 |  48.31 |   4.02|
| [XXH-64](raw/XXH-64.txt) | 64 | 9 | 250 |  58.59 |   3.99|
| [rust-ahash](raw/rust-ahash.txt) | 64 | 9 | 250 |  75.82 |   2.51|
| [FarmHash-32.NT](raw/FarmHash-32.NT.txt) | 32 | 10 | 250 |  57.83 |   7.62|
| [FarmHash-128.CC.seed2](raw/FarmHash-128.CC.seed2.txt) | 128 | 10 | 250 |  74.26 |   4.84|
| [falkhash1](raw/falkhash1.txt) | 128 | 11 | 250 |  89.94 |  19.79|
| [perl-zaphod32](raw/perl-zaphod32.txt) | 32 | 13 | 250 |  45.48 |   1.30|
| [CityHashCrc-128.seed2](raw/CityHashCrc-128.seed2.txt) | 128 | 13 | 250 |  75.27 |   5.98|
| [perl-stadtx](raw/perl-stadtx.txt) | 64 | 14 | 250 |  44.52 |   4.73|
| [TinySipHash](raw/TinySipHash.txt) | 64 | 14 | 250 |  47.66 |   1.50|
| [SpookyHash2-128](raw/SpookyHash2-128.txt) | 128 | 14 | 250 |  70.46 |   4.40|
| [wyhash](raw/wyhash.txt) | 64 | 15 | 250 |  35.26 |   6.95|
| [XXH3-64.regen](raw/XXH3-64.regen.txt) | 64 | 15 | 250 |  35.72 |  12.80|
| [wyhash.strict](raw/wyhash.strict.txt) | 64 | 15 | 250 |  37.46 |   5.78|
| [SpookyHash1-128](raw/SpookyHash1-128.txt) | 128 | 16 | 250 |  69.26 |   4.40|
| [pengyhash](raw/pengyhash.txt) | 64 | 16 | 250 |  95.78 |   3.78|
| [mum1.inexact.unroll2](raw/mum1.inexact.unroll2.txt) | 64 | 17 | 250 |  52.53 |   1.20|
| [mum1.inexact.unroll3](raw/mum1.inexact.unroll3.txt) | 64 | 17 | 250 |  52.85 |   1.31|
| [mum1.inexact.unroll4](raw/mum1.inexact.unroll4.txt) | 64 | 17 | 250 |  53.02 |   1.86|
| [mir.inexact](raw/mir.inexact.txt) | 64 | 17 | 250 |  54.60 |   1.33|
| [mum1.inexact.unroll1](raw/mum1.inexact.unroll1.txt) | 64 | 17 | 250 |  56.36 |   1.15|
| [MetroHash-128](raw/MetroHash-128.txt) | 128 | 17 | 250 |  58.86 |   5.00|
| [floppsyhash](raw/floppsyhash.txt) | 64 | 17 | 235 | 738.98 |   0.05|
| [mum1.exact.unroll2](raw/mum1.exact.unroll2.txt) | 64 | 18 | 250 |  40.18 |   4.15|
| [mum1.exact.unroll4](raw/mum1.exact.unroll4.txt) | 64 | 18 | 250 |  40.29 |   3.98|
| [mum1.exact.unroll3](raw/mum1.exact.unroll3.txt) | 64 | 18 | 250 |  40.51 |   4.36|
| [mum1.exact.unroll1](raw/mum1.exact.unroll1.txt) | 64 | 18 | 250 |  42.49 |   2.54|
| [mir.exact](raw/mir.exact.txt) | 64 | 18 | 250 |  43.88 |   2.21|
| [t1ha0](raw/t1ha0.txt) | 64 | 18 | 250 |  51.51 |   2.42|
| [t1ha2-64.incr](raw/t1ha2-64.incr.txt) | 64 | 18 | 250 |  84.19 |   4.86|
| [XXH3-128.regen](raw/XXH3-128.regen.txt) | 128 | 19 | 250 |  41.50 |  12.80|
| [FARSH-32.tweaked](raw/FARSH-32.tweaked.txt) | 32 | 19 | 250 |  69.66 |  14.02|
| [FARSH-64.tweaked](raw/FARSH-64.tweaked.txt) | 64 | 20 | 250 | 122.62 |   6.85|
| [FARSH-256.tweaked](raw/FARSH-256.tweaked.txt) | 256 | 20 | 235 | 481.07 |   1.74|
| [MetroHash-128.var1](raw/MetroHash-128.var1.txt) | 128 | 21 | 250 |  59.00 |   5.11|
| [CityHashCrc-256](raw/CityHashCrc-256.txt) | 256 | 21 | 238 | 189.40 |   6.00|
| [MetroHash-128.var2](raw/MetroHash-128.var2.txt) | 128 | 22 | 250 |  59.00 |   5.11|
| [CLhash.bitmix](raw/CLhash.bitmix.txt) | 64 | 22 | 250 |  66.60 |   7.32|
| [prvhash-128](raw/prvhash-128.txt) | 128 | 23 | 238 |  81.86 |   0.93|
| [t1ha2-128.incr](raw/t1ha2-128.incr.txt) | 128 | 23 | 250 | 109.86 |   4.86|
| [FARSH-128.tweaked](raw/FARSH-128.tweaked.txt) | 128 | 23 | 238 | 240.17 |   3.41|
| [mum3.exact.unroll1](raw/mum3.exact.unroll1.txt) | 64 | 25 | 250 |  35.50 |   2.61|
| [rust-ahash.noshuf](raw/rust-ahash.noshuf.txt) | 64 | 25 | 250 |  80.40 |   0.64|
| [XXH3-64](raw/XXH3-64.txt) | 64 | 28 | 250 |  36.62 |  12.74|
| [MetroHash-64](raw/MetroHash-64.txt) | 64 | 29 | 250 |  48.35 |   5.04|
| [MetroHash-64.var2](raw/MetroHash-64.var2.txt) | 64 | 29 | 250 |  48.49 |   4.97|
| [tabulation-64](raw/tabulation-64.txt) | 64 | 30 | 252 |  43.85 |   3.01|
| [prvhash-64](raw/prvhash-64.txt) | 64 | 30 | 238 |  56.78 |   0.97|
| [mum3.exact.unroll2](raw/mum3.exact.unroll2.txt) | 64 | 33 | 250 |  33.34 |   5.04|
| [MetroHash-64.var1](raw/MetroHash-64.var1.txt) | 64 | 33 | 250 |  48.39 |   4.98|
| [poly-mersenne.deg2](raw/poly-mersenne.deg2.txt) | 32 | 34 | 240 |  67.57 |   0.50|
| [mum3.exact.unroll3](raw/mum3.exact.unroll3.txt) | 64 | 36 | 250 |  33.44 |   5.94|
| [mum3.exact.unroll4](raw/mum3.exact.unroll4.txt) | 64 | 36 | 250 |  33.95 |   5.84|
| [UMASH-64.reseed](raw/UMASH-64.reseed.txt) | 64 | 36 | 250 |  47.93 |   6.08|
| [mx3.v2](raw/mx3.v2.txt) | 64 | 36 | 250 |  57.55 |   3.21|
| [HalftimeHash-64](raw/HalftimeHash-64.txt) | 64 | 36 | 250 |  89.63 |   1.98|
| [XXH3-128](raw/XXH3-128.txt) | 128 | 37 | 250 |  42.52 |  12.78|
| [UMASH-128.reseed](raw/UMASH-128.reseed.txt) | 128 | 37 | 250 |  51.10 |   3.70|
| [mx3.v3](raw/mx3.v3.txt) | 64 | 37 | 250 |  55.38 |   3.75|
| [FarmHash-64.UO](raw/FarmHash-64.UO.txt) | 64 | 39 | 250 |  57.48 |   5.11|
| [FarmHash-64.TE](raw/FarmHash-64.TE.txt) | 64 | 39 | 250 |  57.94 |   7.74|
| [aesnihash-peterrk](raw/aesnihash-peterrk.txt) | 128 | 42 | 250 |  38.60 |   9.49|
| [FarmHash-32.MK](raw/FarmHash-32.MK.txt) | 32 | 42 | 250 |  48.82 |   1.51|
| [Abseil64-city](raw/Abseil64-city.txt) | 64 | 43 | 250 |  44.07 |   4.29|
| [Abseil64-llh](raw/Abseil64-llh.txt) | 64 | 43 | 250 |  45.14 |   6.56|
| [Abseil-lowlevel](raw/Abseil-lowlevel.txt) | 64 | 45 | 250 |  35.10 |   6.92|
| [mum2.inexact.unroll1](raw/mum2.inexact.unroll1.txt) | 64 | 45 | 250 |  48.80 |   1.15|
| [mx3.v1](raw/mx3.v1.txt) | 64 | 45 | 250 |  55.52 |   3.21|
| [seahash](raw/seahash.txt) | 64 | 45 | 250 |  61.18 |   2.66|
| [mum2.exact.unroll1](raw/mum2.exact.unroll1.txt) | 64 | 46 | 250 |  38.56 |   2.61|
| [MetroHashCrc-64.var1](raw/MetroHashCrc-64.var1.txt) | 64 | 46 | 250 |  52.48 |   7.89|
| [MetroHashCrc-64.var2](raw/MetroHashCrc-64.var2.txt) | 64 | 47 | 250 |  52.46 |   7.96|
| [FarmHash-64.NA](raw/FarmHash-64.NA.txt) | 64 | 47 | 250 |  57.64 |   4.68|
| [CityHash-64](raw/CityHash-64.txt) | 64 | 47 | 250 |  57.65 |   4.74|
| [FarmHash-32.SA](raw/FarmHash-32.SA.txt) | 32 | 50 | 250 |  48.71 |   4.99|
| [MetroHashCrc-128.var2](raw/MetroHashCrc-128.var2.txt) | 128 | 50 | 250 |  64.37 |   7.96|
| [MetroHashCrc-128.var1](raw/MetroHashCrc-128.var1.txt) | 128 | 50 | 250 |  64.38 |   7.96|
| [HalftimeHash-256](raw/HalftimeHash-256.txt) | 64 | 50 | 250 | 105.11 |  11.70|
| [FarmHash-32.SU](raw/FarmHash-32.SU.txt) | 32 | 51 | 250 |  48.70 |   5.97|
| [FarmHash-32.CC](raw/FarmHash-32.CC.txt) | 32 | 51 | 250 |  48.85 |   1.90|
| [HalftimeHash-128](raw/HalftimeHash-128.txt) | 64 | 51 | 250 | 101.52 |   6.84|
| [AquaHash](raw/AquaHash.txt) | 128 | 56 | 250 |  40.28 |  15.92|
| [VHASH.32](raw/VHASH.32.txt) | 32 | 56 | 250 |  97.22 |   5.19|
| [VHASH](raw/VHASH.txt) | 64 | 60 | 250 |  97.32 |   5.20|
| [HalftimeHash-512](raw/HalftimeHash-512.txt) | 64 | 60 | 250 | 119.85 |   9.50|
| [fasthash-32](raw/fasthash-32.txt) | 32 | 61 | 250 |  47.39 |   2.00|
| [mum2.exact.unroll2](raw/mum2.exact.unroll2.txt) | 64 | 63 | 250 |  36.40 |   4.12|
| [mum2.inexact.unroll2](raw/mum2.inexact.unroll2.txt) | 64 | 63 | 250 |  44.31 |   1.26|
| [t1ha1](raw/t1ha1.txt) | 64 | 64 | 250 |  36.27 |   4.57|
| [CityHash-32](raw/CityHash-32.txt) | 32 | 70 | 250 |  49.66 |   1.91|
| [mum2.exact.unroll3](raw/mum2.exact.unroll3.txt) | 64 | 71 | 250 |  36.44 |   4.36|
| [mum2.inexact.unroll3](raw/mum2.inexact.unroll3.txt) | 64 | 71 | 250 |  44.42 |   1.32|
| [perl-zaphod32.sbox128](raw/perl-zaphod32.sbox128.txt) | 32 | 75 | 250 |  33.16 |   1.31|
| [perl-zaphod32.sbox96](raw/perl-zaphod32.sbox96.txt) | 32 | 75 | 250 |  33.31 |   1.31|
| [perl-zaphod32.sbox128.old](raw/perl-zaphod32.sbox128.old.txt) | 32 | 76 | 250 |  33.24 |   1.31|
| [NMHASH](raw/NMHASH.txt) | 32 | 77 | 250 |  58.79 |   7.69|
| [mum2.exact.unroll4](raw/mum2.exact.unroll4.txt) | 64 | 78 | 250 |  35.89 |   3.99|
| [mum2.inexact.unroll4](raw/mum2.inexact.unroll4.txt) | 64 | 78 | 250 |  44.71 |   1.87|
| [MurmurHash3-32](raw/MurmurHash3-32.txt) | 32 | 83 | 250 |  50.86 |   1.00|
| [XXH-32](raw/XXH-32.txt) | 32 | 84 | 250 |  50.45 |   2.00|
| [MurmurHash3-128](raw/MurmurHash3-128.txt) | 128 | 87 | 250 |  53.64 |   2.37|
| [lookup3.32](raw/lookup3.32.txt) | 32 | 91 | 238 |  42.00 |   0.81|
| [floppsyhash.old](raw/floppsyhash.old.txt) | 64 | 94 | 235 | 713.40 |   0.04|
| [mum3.inexact.unroll1](raw/mum3.inexact.unroll1.txt) | 64 | 99 | 250 |  44.39 |   1.39|
| [fasthash-64](raw/fasthash-64.txt) | 64 | 99 | 250 |  45.72 |   2.00|
| [NMHASHX](raw/NMHASHX.txt) | 32 | 100 | 250 |  45.81 |   7.70|
| [MurmurHash2-64](raw/MurmurHash2-64.txt) | 64 | 101 | 250 |  46.05 |   2.00|
| [MurmurHash3-128.int32](raw/MurmurHash3-128.int32.txt) | 128 | 102 | 250 |  52.83 |   1.64|
| [tabulation-32](raw/tabulation-32.txt) | 32 | 104 | 252 |  33.94 |   2.20|
| [MurmurHash1](raw/MurmurHash1.txt) | 32 | 116 | 238 |  52.36 |   0.67|
| [mum3.inexact.unroll2](raw/mum3.inexact.unroll2.txt) | 64 | 117 | 250 |  39.78 |   1.80|
| [lookup3](raw/lookup3.txt) | 64 | 123 | 238 |  42.03 |   0.81|
| [UMASH-64](raw/UMASH-64.txt) | 64 | 127 | 250 |  47.77 |   6.07|
| [mum3.inexact.unroll3](raw/mum3.inexact.unroll3.txt) | 64 | 128 | 250 |  40.21 |   2.02|
| [UMASH-128](raw/UMASH-128.txt) | 128 | 128 | 250 |  51.27 |   3.70|
| [mum3.inexact.unroll4](raw/mum3.inexact.unroll4.txt) | 64 | 132 | 250 |  41.11 |   1.98|
| [poly-mersenne.deg1](raw/poly-mersenne.deg1.txt) | 32 | 134 | 240 |  59.15 |   0.50|
| [perl-jenkins-hard](raw/perl-jenkins-hard.txt) | 32 | 134 | 235 | 121.01 |   0.20|
| [MurmurHash2a](raw/MurmurHash2a.txt) | 32 | 150 | 250 |  49.75 |   1.00|
| [Crap8](raw/Crap8.txt) | 32 | 161 | 250 |  40.02 |   1.00|
| [poly-mersenne.deg0](raw/poly-mersenne.deg0.txt) | 32 | 162 | 240 |  49.76 |   0.50|
| [perl-jenkins](raw/perl-jenkins.txt) | 32 | 164 | 235 | 101.00 |   0.20|
| [MurmurHash2-32](raw/MurmurHash2-32.txt) | 32 | 173 | 250 |  44.94 |   1.00|
| [FNV-Mulvey](raw/FNV-Mulvey.txt) | 32 | 192 | 235 |  89.00 |   0.25|
| [MicroOAAT](raw/MicroOAAT.txt) | 32 | 195 | 235 |  82.23 |   0.24|
| [CLhash](raw/CLhash.txt) | 64 | 198 | 250 |  50.86 |   7.35|
| [MurmurHash2-64.int32](raw/MurmurHash2-64.int32.txt) | 64 | 207 | 250 |  50.62 |   1.33|
| [Pearson-64](raw/Pearson-64.txt) | 64 | 219 | 235 | 131.08 |   0.14|
| [SuperFastHash](raw/SuperFastHash.txt) | 32 | 220 | 238 |  51.13 |   0.78|
| [Abseil32](raw/Abseil32.txt) | 64 | 221 | 250 |  55.31 |   1.81|
| [Pearson-128](raw/Pearson-128.txt) | 128 | 222 | 235 | 127.01 |   0.14|
| [Pearson-256](raw/Pearson-256.txt) | 256 | 222 | 235 | 131.95 |   0.14|
| [pair-multiply-shift-32](raw/pair-multiply-shift-32.txt) | 32 | 226 | 250 |  28.97 |   2.22|
| [FNV-1a-32](raw/FNV-1a-32.txt) | 32 | 227 | 235 |  79.02 |   0.25|
| [multiply-shift-32](raw/multiply-shift-32.txt) | 32 | 230 | 250 |  24.64 |   1.51|
| [pair-multiply-shift](raw/pair-multiply-shift.txt) | 64 | 230 | 250 |  31.70 |   1.92|
| [FNV-YoshimitsuTRIAD](raw/FNV-YoshimitsuTRIAD.txt) | 32 | 230 | 250 |  32.17 |   5.25|
| [perl-djb2](raw/perl-djb2.txt) | 32 | 230 | 235 |  61.02 |   0.33|
| [perl-sdbm](raw/perl-sdbm.txt) | 32 | 230 | 235 |  76.01 |   0.25|
| [FNV-1a-64](raw/FNV-1a-64.txt) | 64 | 230 | 235 |  79.00 |   0.25|
| [x17](raw/x17.txt) | 32 | 230 | 235 |  79.04 |   0.25|
| [FNV-1a-128](raw/FNV-1a-128.txt) | 128 | 230 | 235 |  99.07 |   0.19|
| [multiply-shift](raw/multiply-shift.txt) | 64 | 231 | 250 |  30.56 |   1.80|
| [CRC-32C](raw/CRC-32C.txt) | 32 | 236 | 250 |  36.79 |   7.69|
| [Fletcher-32](raw/Fletcher-32.txt) | 32 | 239 | 250 |  39.04 |   1.60|
| [Fletcher-64](raw/Fletcher-64.txt) | 64 | 242 | 250 |  39.27 |   2.86|


Hashes that pass Sanity tests, but fail others, sorted by average short input speed and then failing tests.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [multiply-shift-32](raw/multiply-shift-32.txt) | 32 | 230 | 250 |  24.64 |   1.51|
| [pair-multiply-shift-32](raw/pair-multiply-shift-32.txt) | 32 | 226 | 250 |  28.97 |   2.22|
| [multiply-shift](raw/multiply-shift.txt) | 64 | 231 | 250 |  30.56 |   1.80|
| [pair-multiply-shift](raw/pair-multiply-shift.txt) | 64 | 230 | 250 |  31.70 |   1.92|
| [FNV-YoshimitsuTRIAD](raw/FNV-YoshimitsuTRIAD.txt) | 32 | 230 | 250 |  32.17 |   5.25|
| [perl-zaphod32.sbox128](raw/perl-zaphod32.sbox128.txt) | 32 | 75 | 250 |  33.16 |   1.31|
| [perl-zaphod32.sbox128.old](raw/perl-zaphod32.sbox128.old.txt) | 32 | 76 | 250 |  33.24 |   1.31|
| [perl-zaphod32.sbox96](raw/perl-zaphod32.sbox96.txt) | 32 | 75 | 250 |  33.31 |   1.31|
| [mum3.exact.unroll2](raw/mum3.exact.unroll2.txt) | 64 | 33 | 250 |  33.34 |   5.04|
| [mum3.exact.unroll3](raw/mum3.exact.unroll3.txt) | 64 | 36 | 250 |  33.44 |   5.94|
| [tabulation-32](raw/tabulation-32.txt) | 32 | 104 | 252 |  33.94 |   2.20|
| [mum3.exact.unroll4](raw/mum3.exact.unroll4.txt) | 64 | 36 | 250 |  33.95 |   5.84|
| [Abseil-lowlevel](raw/Abseil-lowlevel.txt) | 64 | 45 | 250 |  35.10 |   6.92|
| [wyhash](raw/wyhash.txt) | 64 | 15 | 250 |  35.26 |   6.95|
| [mum3.exact.unroll1](raw/mum3.exact.unroll1.txt) | 64 | 25 | 250 |  35.50 |   2.61|
| [XXH3-64.regen](raw/XXH3-64.regen.txt) | 64 | 15 | 250 |  35.72 |  12.80|
| [mum2.exact.unroll4](raw/mum2.exact.unroll4.txt) | 64 | 78 | 250 |  35.89 |   3.99|
| [t1ha1](raw/t1ha1.txt) | 64 | 64 | 250 |  36.27 |   4.57|
| [mum2.exact.unroll2](raw/mum2.exact.unroll2.txt) | 64 | 63 | 250 |  36.40 |   4.12|
| [mum2.exact.unroll3](raw/mum2.exact.unroll3.txt) | 64 | 71 | 250 |  36.44 |   4.36|
| [XXH3-64](raw/XXH3-64.txt) | 64 | 28 | 250 |  36.62 |  12.74|
| [CRC-32C](raw/CRC-32C.txt) | 32 | 236 | 250 |  36.79 |   7.69|
| [wyhash-32](raw/wyhash-32.txt) | 32 | 2 | 250 |  37.00 |   1.33|
| [wyhash.strict](raw/wyhash.strict.txt) | 64 | 15 | 250 |  37.46 |   5.78|
| [mum2.exact.unroll1](raw/mum2.exact.unroll1.txt) | 64 | 46 | 250 |  38.56 |   2.61|
| [aesnihash-peterrk](raw/aesnihash-peterrk.txt) | 128 | 42 | 250 |  38.60 |   9.49|
| [Fletcher-32](raw/Fletcher-32.txt) | 32 | 239 | 250 |  39.04 |   1.60|
| [Fletcher-64](raw/Fletcher-64.txt) | 64 | 242 | 250 |  39.27 |   2.86|
| [mum3.inexact.unroll2](raw/mum3.inexact.unroll2.txt) | 64 | 117 | 250 |  39.78 |   1.80|
| [Crap8](raw/Crap8.txt) | 32 | 161 | 250 |  40.02 |   1.00|
| [mum1.exact.unroll2](raw/mum1.exact.unroll2.txt) | 64 | 18 | 250 |  40.18 |   4.15|
| [mum3.inexact.unroll3](raw/mum3.inexact.unroll3.txt) | 64 | 128 | 250 |  40.21 |   2.02|
| [AquaHash](raw/AquaHash.txt) | 128 | 56 | 250 |  40.28 |  15.92|
| [mum1.exact.unroll4](raw/mum1.exact.unroll4.txt) | 64 | 18 | 250 |  40.29 |   3.98|
| [mum1.exact.unroll3](raw/mum1.exact.unroll3.txt) | 64 | 18 | 250 |  40.51 |   4.36|
| [mum3.inexact.unroll4](raw/mum3.inexact.unroll4.txt) | 64 | 132 | 250 |  41.11 |   1.98|
| [XXH3-128.regen](raw/XXH3-128.regen.txt) | 128 | 19 | 250 |  41.50 |  12.80|
| [lookup3.32](raw/lookup3.32.txt) | 32 | 91 | 238 |  42.00 |   0.81|
| [lookup3](raw/lookup3.txt) | 64 | 123 | 238 |  42.03 |   0.81|
| [mum1.exact.unroll1](raw/mum1.exact.unroll1.txt) | 64 | 18 | 250 |  42.49 |   2.54|
| [XXH3-128](raw/XXH3-128.txt) | 128 | 37 | 250 |  42.52 |  12.78|
| [tabulation-64](raw/tabulation-64.txt) | 64 | 30 | 252 |  43.85 |   3.01|
| [mir.exact](raw/mir.exact.txt) | 64 | 18 | 250 |  43.88 |   2.21|
| [Abseil64-city](raw/Abseil64-city.txt) | 64 | 43 | 250 |  44.07 |   4.29|
| [mum2.inexact.unroll2](raw/mum2.inexact.unroll2.txt) | 64 | 63 | 250 |  44.31 |   1.26|
| [mum3.inexact.unroll1](raw/mum3.inexact.unroll1.txt) | 64 | 99 | 250 |  44.39 |   1.39|
| [mum2.inexact.unroll3](raw/mum2.inexact.unroll3.txt) | 64 | 71 | 250 |  44.42 |   1.32|
| [perl-stadtx](raw/perl-stadtx.txt) | 64 | 14 | 250 |  44.52 |   4.73|
| [mum2.inexact.unroll4](raw/mum2.inexact.unroll4.txt) | 64 | 78 | 250 |  44.71 |   1.87|
| [MurmurHash2-32](raw/MurmurHash2-32.txt) | 32 | 173 | 250 |  44.94 |   1.00|
| [Abseil64-llh](raw/Abseil64-llh.txt) | 64 | 43 | 250 |  45.14 |   6.56|
| [perl-zaphod32](raw/perl-zaphod32.txt) | 32 | 13 | 250 |  45.48 |   1.30|
| [fasthash-64](raw/fasthash-64.txt) | 64 | 99 | 250 |  45.72 |   2.00|
| [NMHASHX](raw/NMHASHX.txt) | 32 | 100 | 250 |  45.81 |   7.70|
| [MurmurHash2-64](raw/MurmurHash2-64.txt) | 64 | 101 | 250 |  46.05 |   2.00|
| [t1ha0.aesA](raw/t1ha0.aesA.txt) | 64 | 5 | 250 |  46.19 |   9.10|
| [t1ha0.aesB](raw/t1ha0.aesB.txt) | 64 | 5 | 250 |  46.49 |  21.29|
| [t1ha2-64](raw/t1ha2-64.txt) | 64 | 3 | 250 |  46.56 |   4.62|
| [fasthash-32](raw/fasthash-32.txt) | 32 | 61 | 250 |  47.39 |   2.00|
| [TinySipHash](raw/TinySipHash.txt) | 64 | 14 | 250 |  47.66 |   1.50|
| [UMASH-64](raw/UMASH-64.txt) | 64 | 127 | 250 |  47.77 |   6.07|
| [UMASH-64.reseed](raw/UMASH-64.reseed.txt) | 64 | 36 | 250 |  47.93 |   6.08|
| [polymurhash-tweakseed](raw/polymurhash-tweakseed.txt) | 64 | 9 | 250 |  48.31 |   4.02|
| [MetroHash-64](raw/MetroHash-64.txt) | 64 | 29 | 250 |  48.35 |   5.04|
| [MetroHash-64.var1](raw/MetroHash-64.var1.txt) | 64 | 33 | 250 |  48.39 |   4.98|
| [MetroHash-64.var2](raw/MetroHash-64.var2.txt) | 64 | 29 | 250 |  48.49 |   4.97|
| [FarmHash-32.SU](raw/FarmHash-32.SU.txt) | 32 | 51 | 250 |  48.70 |   5.97|
| [FarmHash-32.SA](raw/FarmHash-32.SA.txt) | 32 | 50 | 250 |  48.71 |   4.99|
| [mum2.inexact.unroll1](raw/mum2.inexact.unroll1.txt) | 64 | 45 | 250 |  48.80 |   1.15|
| [FarmHash-32.MK](raw/FarmHash-32.MK.txt) | 32 | 42 | 250 |  48.82 |   1.51|
| [FarmHash-32.CC](raw/FarmHash-32.CC.txt) | 32 | 51 | 250 |  48.85 |   1.90|
| [CityHash-32](raw/CityHash-32.txt) | 32 | 70 | 250 |  49.66 |   1.91|
| [MurmurHash2a](raw/MurmurHash2a.txt) | 32 | 150 | 250 |  49.75 |   1.00|
| [poly-mersenne.deg0](raw/poly-mersenne.deg0.txt) | 32 | 162 | 240 |  49.76 |   0.50|
| [XXH-32](raw/XXH-32.txt) | 32 | 84 | 250 |  50.45 |   2.00|
| [MurmurHash2-64.int32](raw/MurmurHash2-64.int32.txt) | 64 | 207 | 250 |  50.62 |   1.33|
| [MurmurHash3-32](raw/MurmurHash3-32.txt) | 32 | 83 | 250 |  50.86 |   1.00|
| [CLhash](raw/CLhash.txt) | 64 | 198 | 250 |  50.86 |   7.35|
| [UMASH-128.reseed](raw/UMASH-128.reseed.txt) | 128 | 37 | 250 |  51.10 |   3.70|
| [SuperFastHash](raw/SuperFastHash.txt) | 32 | 220 | 238 |  51.13 |   0.78|
| [UMASH-128](raw/UMASH-128.txt) | 128 | 128 | 250 |  51.27 |   3.70|
| [t1ha0](raw/t1ha0.txt) | 64 | 18 | 250 |  51.51 |   2.42|
| [MurmurHash1](raw/MurmurHash1.txt) | 32 | 116 | 238 |  52.36 |   0.67|
| [MetroHashCrc-64.var2](raw/MetroHashCrc-64.var2.txt) | 64 | 47 | 250 |  52.46 |   7.96|
| [MetroHashCrc-64.var1](raw/MetroHashCrc-64.var1.txt) | 64 | 46 | 250 |  52.48 |   7.89|
| [mum1.inexact.unroll2](raw/mum1.inexact.unroll2.txt) | 64 | 17 | 250 |  52.53 |   1.20|
| [MurmurHash3-128.int32](raw/MurmurHash3-128.int32.txt) | 128 | 102 | 250 |  52.83 |   1.64|
| [mum1.inexact.unroll3](raw/mum1.inexact.unroll3.txt) | 64 | 17 | 250 |  52.85 |   1.31|
| [mum1.inexact.unroll4](raw/mum1.inexact.unroll4.txt) | 64 | 17 | 250 |  53.02 |   1.86|
| [MurmurHash3-128](raw/MurmurHash3-128.txt) | 128 | 87 | 250 |  53.64 |   2.37|
| [mir.inexact](raw/mir.inexact.txt) | 64 | 17 | 250 |  54.60 |   1.33|
| [Abseil32](raw/Abseil32.txt) | 64 | 221 | 250 |  55.31 |   1.81|
| [mx3.v3](raw/mx3.v3.txt) | 64 | 37 | 250 |  55.38 |   3.75|
| [mx3.v1](raw/mx3.v1.txt) | 64 | 45 | 250 |  55.52 |   3.21|
| [mum1.inexact.unroll1](raw/mum1.inexact.unroll1.txt) | 64 | 17 | 250 |  56.36 |   1.15|
| [prvhash-64](raw/prvhash-64.txt) | 64 | 30 | 238 |  56.78 |   0.97|
| [FarmHash-64.UO](raw/FarmHash-64.UO.txt) | 64 | 39 | 250 |  57.48 |   5.11|
| [mx3.v2](raw/mx3.v2.txt) | 64 | 36 | 250 |  57.55 |   3.21|
| [FarmHash-64.NA](raw/FarmHash-64.NA.txt) | 64 | 47 | 250 |  57.64 |   4.68|
| [CityHash-64](raw/CityHash-64.txt) | 64 | 47 | 250 |  57.65 |   4.74|
| [FarmHash-32.NT](raw/FarmHash-32.NT.txt) | 32 | 10 | 250 |  57.83 |   7.62|
| [FarmHash-64.TE](raw/FarmHash-64.TE.txt) | 64 | 39 | 250 |  57.94 |   7.74|
| [XXH-64](raw/XXH-64.txt) | 64 | 9 | 250 |  58.59 |   3.99|
| [NMHASH](raw/NMHASH.txt) | 32 | 77 | 250 |  58.79 |   7.69|
| [MetroHash-128](raw/MetroHash-128.txt) | 128 | 17 | 250 |  58.86 |   5.00|
| [MetroHash-128.var1](raw/MetroHash-128.var1.txt) | 128 | 21 | 250 |  59.00 |   5.11|
| [MetroHash-128.var2](raw/MetroHash-128.var2.txt) | 128 | 22 | 250 |  59.00 |   5.11|
| [poly-mersenne.deg1](raw/poly-mersenne.deg1.txt) | 32 | 134 | 240 |  59.15 |   0.50|
| [perl-djb2](raw/perl-djb2.txt) | 32 | 230 | 235 |  61.02 |   0.33|
| [seahash](raw/seahash.txt) | 64 | 45 | 250 |  61.18 |   2.66|
| [MetroHashCrc-128.var2](raw/MetroHashCrc-128.var2.txt) | 128 | 50 | 250 |  64.37 |   7.96|
| [MetroHashCrc-128.var1](raw/MetroHashCrc-128.var1.txt) | 128 | 50 | 250 |  64.38 |   7.96|
| [SpookyHash1-64](raw/SpookyHash1-64.txt) | 64 | 4 | 250 |  64.82 |   4.40|
| [SpookyHash2-64](raw/SpookyHash2-64.txt) | 64 | 7 | 250 |  66.26 |   4.40|
| [CLhash.bitmix](raw/CLhash.bitmix.txt) | 64 | 22 | 250 |  66.60 |   7.32|
| [t1ha2-128](raw/t1ha2-128.txt) | 128 | 1 | 250 |  67.34 |   4.89|
| [MeowHash](raw/MeowHash.txt) | 128 | 1 | 250 |  67.50 |  12.17|
| [poly-mersenne.deg2](raw/poly-mersenne.deg2.txt) | 32 | 34 | 240 |  67.57 |   0.50|
| [SpookyHash1-128](raw/SpookyHash1-128.txt) | 128 | 16 | 250 |  69.26 |   4.40|
| [FARSH-32.tweaked](raw/FARSH-32.tweaked.txt) | 32 | 19 | 250 |  69.66 |  14.02|
| [SpookyHash2-128](raw/SpookyHash2-128.txt) | 128 | 14 | 250 |  70.46 |   4.40|
| [FarmHash-128.CC.seed2](raw/FarmHash-128.CC.seed2.txt) | 128 | 10 | 250 |  74.26 |   4.84|
| [FarmHash-128.CC.seed1](raw/FarmHash-128.CC.seed1.txt) | 128 | 2 | 250 |  74.40 |   4.84|
| [FarmHash-128.CM.seed2](raw/FarmHash-128.CM.seed2.txt) | 128 | 8 | 250 |  74.60 |   2.61|
| [CityHashCrc-128.seed3](raw/CityHashCrc-128.seed3.txt) | 128 | 7 | 250 |  75.10 |   5.98|
| [CityHashCrc-128.seed1](raw/CityHashCrc-128.seed1.txt) | 128 | 7 | 250 |  75.12 |   6.00|
| [CityHashCrc-128.seed2](raw/CityHashCrc-128.seed2.txt) | 128 | 13 | 250 |  75.27 |   5.98|
| [rust-ahash](raw/rust-ahash.txt) | 64 | 9 | 250 |  75.82 |   2.51|
| [FarmHash-128.CC.seed3](raw/FarmHash-128.CC.seed3.txt) | 128 | 2 | 250 |  75.92 |   4.85|
| [perl-sdbm](raw/perl-sdbm.txt) | 32 | 230 | 235 |  76.01 |   0.25|
| [FNV-1a-64](raw/FNV-1a-64.txt) | 64 | 230 | 235 |  79.00 |   0.25|
| [FNV-1a-32](raw/FNV-1a-32.txt) | 32 | 227 | 235 |  79.02 |   0.25|
| [x17](raw/x17.txt) | 32 | 230 | 235 |  79.04 |   0.25|
| [rust-ahash.noshuf](raw/rust-ahash.noshuf.txt) | 64 | 25 | 250 |  80.40 |   0.64|
| [prvhash-128](raw/prvhash-128.txt) | 128 | 23 | 238 |  81.86 |   0.93|
| [MicroOAAT](raw/MicroOAAT.txt) | 32 | 195 | 235 |  82.23 |   0.24|
| [t1ha2-64.incr](raw/t1ha2-64.incr.txt) | 64 | 18 | 250 |  84.19 |   4.86|
| [FNV-Mulvey](raw/FNV-Mulvey.txt) | 32 | 192 | 235 |  89.00 |   0.25|
| [HalftimeHash-64](raw/HalftimeHash-64.txt) | 64 | 36 | 250 |  89.63 |   1.98|
| [falkhash1](raw/falkhash1.txt) | 128 | 11 | 250 |  89.94 |  19.79|
| [falkhash2](raw/falkhash2.txt) | 128 | 7 | 250 |  91.89 |  17.98|
| [pengyhash](raw/pengyhash.txt) | 64 | 16 | 250 |  95.78 |   3.78|
| [VHASH.32](raw/VHASH.32.txt) | 32 | 56 | 250 |  97.22 |   5.19|
| [VHASH](raw/VHASH.txt) | 64 | 60 | 250 |  97.32 |   5.20|
| [FNV-1a-128](raw/FNV-1a-128.txt) | 128 | 230 | 235 |  99.07 |   0.19|
| [perl-jenkins](raw/perl-jenkins.txt) | 32 | 164 | 235 | 101.00 |   0.20|
| [HalftimeHash-128](raw/HalftimeHash-128.txt) | 64 | 51 | 250 | 101.52 |   6.84|
| [HalftimeHash-256](raw/HalftimeHash-256.txt) | 64 | 50 | 250 | 105.11 |  11.70|
| [t1ha2-128.incr](raw/t1ha2-128.incr.txt) | 128 | 23 | 250 | 109.86 |   4.86|
| [HalftimeHash-512](raw/HalftimeHash-512.txt) | 64 | 60 | 250 | 119.85 |   9.50|
| [perl-jenkins-hard](raw/perl-jenkins-hard.txt) | 32 | 134 | 235 | 121.01 |   0.20|
| [FARSH-64.tweaked](raw/FARSH-64.tweaked.txt) | 64 | 20 | 250 | 122.62 |   6.85|
| [Pearson-128](raw/Pearson-128.txt) | 128 | 222 | 235 | 127.01 |   0.14|
| [Pearson-64](raw/Pearson-64.txt) | 64 | 219 | 235 | 131.08 |   0.14|
| [Pearson-256](raw/Pearson-256.txt) | 256 | 222 | 235 | 131.95 |   0.14|
| [chaskey-12](raw/chaskey-12.txt) | 128 | 1 | 235 | 138.37 |   0.25|
| [CityHashCrc-256](raw/CityHashCrc-256.txt) | 256 | 21 | 238 | 189.40 |   6.00|
| [FARSH-128.tweaked](raw/FARSH-128.tweaked.txt) | 128 | 23 | 238 | 240.17 |   3.41|
| [FARSH-256.tweaked](raw/FARSH-256.tweaked.txt) | 256 | 20 | 235 | 481.07 |   1.74|
| [floppsyhash.old](raw/floppsyhash.old.txt) | 64 | 94 | 235 | 713.40 |   0.04|
| [floppsyhash](raw/floppsyhash.txt) | 64 | 17 | 235 | 738.98 |   0.05|
| [beamsplitter](raw/beamsplitter.txt) | 64 | 4 | 235 | 924.27 |   0.18|

Unusable hashes
---------------

Hashes that fail Sanity tests, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [aesrng-32](raw/aesrng-32.txt) | 32 | 2 | 250 |  12.82 | 3448.28|
| [aesrng-64](raw/aesrng-64.txt) | 64 | 2 | 250 |  13.21 | 3493.63|
| [aesrng-128](raw/aesrng-128.txt) | 128 | 2 | 250 |  24.36 | 2948.43|
| [aesrng-160](raw/aesrng-160.txt) | 160 | 2 | 250 |  91.00 | 1649.81|
| [aesrng-256](raw/aesrng-256.txt) | 256 | 2 | 250 |  97.68 | 1663.59|
| [aesrng-224](raw/aesrng-224.txt) | 224 | 2 | 250 |  97.86 | 1673.41|
| [FARSH-32](raw/FARSH-32.txt) | 32 | 28 | 250 |  69.68 |  15.76|
| [FARSH-256](raw/FARSH-256.txt) | 256 | 28 | 235 | 481.44 |   1.99|
| [hasshe2](raw/hasshe2.txt) | 256 | 29 | 238 | 102.80 |   0.93|
| [FARSH-64](raw/FARSH-64.txt) | 64 | 30 | 250 | 121.67 |   7.89|
| [FARSH-128](raw/FARSH-128.txt) | 128 | 33 | 238 | 239.55 |   3.95|
| [XXH3-64.reinit](raw/XXH3-64.reinit.txt) | 64 | 53 | 250 |  35.73 |  12.53|
| [XXH3-128.reinit](raw/XXH3-128.reinit.txt) | 128 | 54 | 250 |  41.49 |  12.83|
| [aesnihash-majek](raw/aesnihash-majek.txt) | 64 | 64 | 250 |  64.00 |   1.78|
| [CrapWow-64](raw/CrapWow-64.txt) | 64 | 137 | 250 |  36.65 |   4.75|
| [khash-64](raw/khash-64.txt) | 64 | 143 | 250 |  47.92 |   1.56|
| [MurmurOAAT](raw/MurmurOAAT.txt) | 32 | 165 | 235 | 111.00 |   0.17|
| [CrapWow](raw/CrapWow.txt) | 32 | 166 | 250 |  30.94 |   2.58|
| [perl-jenkins-old](raw/perl-jenkins-old.txt) | 32 | 173 | 235 | 101.00 |   0.20|
| [khash-32](raw/khash-32.txt) | 32 | 183 | 250 |  59.04 |   1.39|
| [FNV-PippipYurii](raw/FNV-PippipYurii.txt) | 32 | 197 | 250 |  37.36 |   2.00|
| [FNV-Totenschiff](raw/FNV-Totenschiff.txt) | 32 | 206 | 250 |  36.19 |   2.00|
| [rust-fxhash32](raw/rust-fxhash32.txt) | 32 | 209 | 250 |  37.32 |   0.80|
| [rust-fxhash64](raw/rust-fxhash64.txt) | 64 | 219 | 250 |  34.86 |   1.60|
| [jodyhash-32](raw/jodyhash-32.txt) | 32 | 221 | 238 |  44.48 |   0.57|
| [badhash](raw/badhash.txt) | 32 | 226 | 235 |  81.58 |   0.23|
| [jodyhash-64](raw/jodyhash-64.txt) | 64 | 230 | 250 |  34.96 |   1.98|
| [FNV-1a-64.wordwise](raw/FNV-1a-64.wordwise.txt) | 64 | 240 | 250 |  40.78 |   2.00|
| [FNV-1a-32.wordwise](raw/FNV-1a-32.wordwise.txt) | 32 | 242 | 250 |  35.68 |   1.00|
| [fletcher2.64](raw/fletcher2.64.txt) | 64 | 244 | 250 |  27.18 |   4.93|
| [fletcher2](raw/fletcher2.txt) | 128 | 244 | 250 |  29.98 |   4.92|
| [fibonacci-64](raw/fibonacci-64.txt) | 64 | 246 | 250 |  28.55 |   9.96|
| [donothing-32](raw/donothing-32.txt) | 32 | 247 | 250 |   5.00 | 3729.29|
| [sum32hash](raw/sum32hash.txt) | 32 | 247 | 250 |  20.56 |  26.79|
| [fibonacci-32](raw/fibonacci-32.txt) | 32 | 247 | 250 |  30.93 |  15.90|
| [fletcher4](raw/fletcher4.txt) | 256 | 247 | 250 |  33.74 |   1.91|
| [sum8hash](raw/sum8hash.txt) | 32 | 247 | 250 |  35.72 |   3.39|
| [o1hash](raw/o1hash.txt) | 64 | 248 | 250 |  20.95 | 3691.69|
| [fletcher4.64](raw/fletcher4.64.txt) | 64 | 248 | 250 |  27.10 |   1.91|
| [donothing-128](raw/donothing-128.txt) | 128 | 249 | 250 |   5.00 | 3727.24|
| [donothing-256](raw/donothing-256.txt) | 256 | 249 | 250 |   5.00 | 3727.03|
| [donothing-64](raw/donothing-64.txt) | 64 | 249 | 250 |   5.00 | 3727.01|
| [donothingOAAT-64](raw/donothingOAAT-64.txt) | 64 | 249 | 250 |  45.18 |   3.40|
| [donothingOAAT-32](raw/donothingOAAT-32.txt) | 32 | 249 | 250 |  45.37 |   3.40|
| [donothingOAAT-128](raw/donothingOAAT-128.txt) | 128 | 249 | 250 |  45.41 |   3.42|

All results were generated using: SMHasher3 beta3-c6b9cc18 or SMHasher3 beta3-13-9a00c481
