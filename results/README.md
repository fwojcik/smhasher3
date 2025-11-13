SMHasher3 results summary
=========================

[[_TOC_]]

Passing hashes
--------------

Hashes that currently pass all tests, sorted by average short input speed.

| Hash name | output width | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-----------:|-------------------------:|------------------------:|
| [a5hash-128.64](raw/a5hash-128.64.txt) | 64 | 250 |  24.64 |   6.92|
| [a5hash-32](raw/a5hash-32.txt) | 32 | 250 |  25.81 |   2.36|
| [MuseAir.bfast](raw/MuseAir.bfast.txt) | 64 | 250 |  26.28 |   8.64|
| [a5hash](raw/a5hash.txt) | 64 | 250 |  26.91 |   2.63|
| [MuseAir](raw/MuseAir.txt) | 64 | 250 |  28.45 |   7.19|
| [rust-ahash-fb](raw/rust-ahash-fb.txt) | 64 | 250 |  29.14 |   4.52|
| [rapidhash-nano](raw/rapidhash-nano.txt) | 64 | 250 |  29.83 |   6.98|
| [rapidhash-micro](raw/rapidhash-micro.txt) | 64 | 250 |  30.21 |   7.94|
| [a5hash-128](raw/a5hash-128.txt) | 128 | 250 |  30.27 |   6.92|
| [rapidhash](raw/rapidhash.txt) | 64 | 250 |  30.41 |   8.82|
| [MuseAir-128](raw/MuseAir-128.txt) | 128 | 250 |  30.97 |   7.15|
| [MuseAir-128.bfast](raw/MuseAir-128.bfast.txt) | 128 | 250 |  30.97 |   8.18|
| [rust-ahash-fb.nofold](raw/rust-ahash-fb.nofold.txt) | 64 | 250 |  31.01 |   3.46|
| [rapidhash-nano.protected](raw/rapidhash-nano.protected.txt) | 64 | 250 |  31.36 |   5.69|
| [rapidhash.protected](raw/rapidhash.protected.txt) | 64 | 250 |  31.98 |   6.58|
| [rapidhash-micro.protected](raw/rapidhash-micro.protected.txt) | 64 | 250 |  31.99 |   6.47|
| [komihash](raw/komihash.txt) | 64 | 250 |  32.62 |   6.24|
| [ChibiHash2](raw/ChibiHash2.txt) | 64 | 250 |  34.53 |   6.15|
| [rust-rapidhash.seed](raw/rust-rapidhash.seed.txt) | 64 | 250 |  34.93 |   8.67|
| [rust-rapidhash](raw/rust-rapidhash.txt) | 64 | 250 |  35.01 |   8.66|
| [xmsx](raw/xmsx.txt) | 32 | 250 |  42.56 |   0.67|
| [polymurhash](raw/polymurhash.txt) | 64 | 250 |  42.57 |   4.02|
| [rust-rapidhash.p](raw/rust-rapidhash.p.txt) | 64 | 250 |  45.47 |   3.02|
| [rust-rapidhash.p.seed](raw/rust-rapidhash.p.seed.txt) | 64 | 250 |  45.62 |   3.02|
| [prvhash-64](raw/prvhash-64.txt) | 64 | 238 |  51.07 |   0.94|
| [khashv-64](raw/khashv-64.txt) | 64 | 250 |  56.17 |   3.20|
| [khashv-32](raw/khashv-32.txt) | 32 | 250 |  57.20 |   3.20|
| [SpookyHash1-32](raw/SpookyHash1-32.txt) | 32 | 250 |  58.84 |   4.40|
| [SpookyHash2-32](raw/SpookyHash2-32.txt) | 32 | 250 |  60.20 |   4.40|
| [MeowHash.32](raw/MeowHash.32.txt) | 32 | 250 |  61.50 |  12.44|
| [MeowHash](raw/MeowHash.txt) | 128 | 250 |  61.51 |  12.43|
| [MeowHash.64](raw/MeowHash.64.txt) | 64 | 250 |  61.51 |  12.19|
| [rainbow](raw/rainbow.txt) | 64 | 250 |  61.63 |   1.28|
| [rainbow-128](raw/rainbow-128.txt) | 128 | 250 |  62.06 |   1.27|
| [FarmHash-128.CM.seed1](raw/FarmHash-128.CM.seed1.txt) | 128 | 250 |  69.61 |   2.61|
| [poly-mersenne.deg3](raw/poly-mersenne.deg3.txt) | 32 | 238 |  69.79 |   0.50|
| [FarmHash-128.CM.seed3](raw/FarmHash-128.CM.seed3.txt) | 128 | 250 |  70.50 |   2.61|
| [prvhash-128](raw/prvhash-128.txt) | 128 | 238 |  71.07 |   0.92|
| [HighwayHash-64](raw/HighwayHash-64.txt) | 64 | 238 |  73.30 |   2.90|
| [poly-mersenne.deg4](raw/poly-mersenne.deg4.txt) | 32 | 238 |  78.16 |   0.50|
| [HalfSipHash](raw/HalfSipHash.txt) | 32 | 238 |  81.75 |   0.34|
| [TentHash](raw/TentHash.txt) | 160 | 250 |  84.75 |   1.73|
| [GoodOAAT](raw/GoodOAAT.txt) | 32 | 235 |  86.50 |   0.24|
| [GoodhartHash5](raw/GoodhartHash5.txt) | 128 | 250 |  93.26 |   1.06|
| [chaskey-8.32](raw/chaskey-8.32.txt) | 32 | 238 |  93.69 |   0.37|
| [chaskey-8.64](raw/chaskey-8.64.txt) | 64 | 238 |  95.01 |   0.37|
| [hasshe2.tweaked](raw/hasshe2.tweaked.txt) | 256 | 238 |  97.70 |   0.91|
| [HighwayHash-128](raw/HighwayHash-128.txt) | 128 | 238 |  99.09 |   2.87|
| [PearsonBlock-64](raw/PearsonBlock-64.txt) | 64 | 238 | 101.19 |   0.57|
| [chaskey-8](raw/chaskey-8.txt) | 128 | 238 | 101.72 |   0.37|
| [rainbow-256](raw/rainbow-256.txt) | 256 | 250 | 103.65 |   1.28|
| [PearsonBlock-128](raw/PearsonBlock-128.txt) | 128 | 238 | 109.30 |   0.53|
| [SipHash-1-3](raw/SipHash-1-3.txt) | 64 | 238 | 110.12 |   0.61|
| [SipHash-1-3.folded](raw/SipHash-1-3.folded.txt) | 32 | 238 | 111.38 |   0.61|
| [chaskey-12.32](raw/chaskey-12.32.txt) | 32 | 235 | 123.78 |   0.25|
| [GoodhartHash3](raw/GoodhartHash3.txt) | 128 | 250 | 124.69 |   0.44|
| [GoodhartHash6](raw/GoodhartHash6.txt) | 128 | 250 | 125.26 |   1.06|
| [chaskey-12.64](raw/chaskey-12.64.txt) | 64 | 235 | 125.71 |   0.25|
| [chaskey-12](raw/chaskey-12.txt) | 128 | 235 | 132.50 |   0.25|
| [SipHash-2-4](raw/SipHash-2-4.txt) | 64 | 235 | 152.26 |   0.32|
| [SipHash-2-4.folded](raw/SipHash-2-4.folded.txt) | 32 | 235 | 154.05 |   0.32|
| [HighwayHash-256](raw/HighwayHash-256.txt) | 256 | 238 | 154.48 |   2.88|
| [PearsonBlock-256](raw/PearsonBlock-256.txt) | 256 | 238 | 168.68 |   0.33|
| [rainstorm](raw/rainstorm.txt) | 64 | 238 | 184.06 |   0.58|
| [prvhash-64.incr](raw/prvhash-64.incr.txt) | 64 | 238 | 188.16 |   2.29|
| [rainstorm-128](raw/rainstorm-128.txt) | 128 | 238 | 196.96 |   0.58|
| [Discohash1](raw/Discohash1.txt) | 64 | 238 | 208.67 |   1.34|
| [Discohash2](raw/Discohash2.txt) | 64 | 238 | 214.89 |   1.34|
| [Discohash1-128](raw/Discohash1-128.txt) | 128 | 238 | 239.92 |   1.34|
| [Discohash2-128](raw/Discohash2-128.txt) | 128 | 238 | 241.00 |   1.34|
| [rainstorm-256](raw/rainstorm-256.txt) | 256 | 238 | 241.15 |   0.59|
| [prvhash-128.incr](raw/prvhash-128.incr.txt) | 128 | 238 | 279.13 |   2.17|
| [blake3](raw/blake3.txt) | 256 | 235 | 316.54 |   0.42|
| [SHA-2-224](raw/SHA-2-224.txt) | 224 | 235 | 325.46 |   0.45|
| [ascon-CXOFa-64](raw/ascon-CXOFa-64.txt) | 64 | 235 | 389.85 |   0.08|
| [ascon-CXOFa-32](raw/ascon-CXOFa-32.txt) | 32 | 235 | 390.71 |   0.08|
| [SHA-2-224.64](raw/SHA-2-224.64.txt) | 64 | 235 | 406.07 |   0.45|
| [SHA-2-256.64](raw/SHA-2-256.64.txt) | 64 | 235 | 406.11 |   0.45|
| [blake2s-256.64](raw/blake2s-256.64.txt) | 64 | 235 | 427.19 |   0.18|
| [SHA-2-256](raw/SHA-2-256.txt) | 256 | 235 | 428.33 |   0.45|
| [blake2s-256](raw/blake2s-256.txt) | 256 | 235 | 429.99 |   0.18|
| [blake2s-128](raw/blake2s-128.txt) | 128 | 235 | 430.47 |   0.18|
| [blake2s-160](raw/blake2s-160.txt) | 160 | 235 | 431.01 |   0.18|
| [blake2s-224](raw/blake2s-224.txt) | 224 | 235 | 449.41 |   0.18|
| [ascon-CXOF-32](raw/ascon-CXOF-32.txt) | 32 | 235 | 468.99 |   0.05|
| [ascon-CXOF-64](raw/ascon-CXOF-64.txt) | 64 | 235 | 472.82 |   0.05|
| [RIPEMD-128](raw/RIPEMD-128.txt) | 128 | 235 | 479.70 |   0.15|
| [SHA-1.32](raw/SHA-1.32.txt) | 32 | 235 | 490.07 |   0.48|
| [SHA-1.64](raw/SHA-1.64.txt) | 64 | 235 | 490.61 |   0.48|
| [SHA-1](raw/SHA-1.txt) | 128 | 235 | 490.81 |   0.48|
| [ascon-CXOFa-128](raw/ascon-CXOFa-128.txt) | 128 | 235 | 502.78 |   0.08|
| [MD5](raw/MD5.txt) | 128 | 235 | 520.36 |   0.14|
| [MD5.64](raw/MD5.64.txt) | 64 | 235 | 520.40 |   0.14|
| [MD5.32](raw/MD5.32.txt) | 32 | 235 | 520.66 |   0.14|
| [RIPEMD-256](raw/RIPEMD-256.txt) | 256 | 235 | 557.16 |   0.13|
| [blake2b-160](raw/blake2b-160.txt) | 160 | 235 | 580.75 |   0.26|
| [blake2b-256](raw/blake2b-256.txt) | 256 | 235 | 581.72 |   0.26|
| [blake2b-256.64](raw/blake2b-256.64.txt) | 64 | 235 | 581.72 |   0.26|
| [blake2b-128](raw/blake2b-128.txt) | 128 | 235 | 588.45 |   0.26|
| [blake2b-224](raw/blake2b-224.txt) | 224 | 235 | 602.89 |   0.26|
| [ascon-CXOFa-160](raw/ascon-CXOFa-160.txt) | 160 | 235 | 619.05 |   0.08|
| [ascon-CXOF-128](raw/ascon-CXOF-128.txt) | 128 | 235 | 634.14 |   0.05|
| [RIPEMD-160](raw/RIPEMD-160.txt) | 160 | 235 | 703.02 |   0.10|
| [ascon-CXOFa-224](raw/ascon-CXOFa-224.txt) | 224 | 235 | 739.19 |   0.08|
| [ascon-CXOFa-256](raw/ascon-CXOFa-256.txt) | 256 | 235 | 742.67 |   0.08|
| [ascon-CXOF-160](raw/ascon-CXOF-160.txt) | 160 | 235 | 803.23 |   0.05|
| [ascon-CXOF-224](raw/ascon-CXOF-224.txt) | 224 | 235 | 974.19 |   0.05|
| [ascon-CXOF-256](raw/ascon-CXOF-256.txt) | 256 | 235 | 976.36 |   0.05|
| [SHA-3](raw/SHA-3.txt) | 256 | 235 | 2964.70 |   0.05|
| [SHA-3-256.64](raw/SHA-3-256.64.txt) | 64 | 235 | 2965.13 |   0.05|


Failing hashes
--------------

Hashes that pass Sanity tests, but fail others, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [w1hash](raw/w1hash.txt) | 64 | 1 | 250 |  29.34 |   8.15|
| [t1ha2-128](raw/t1ha2-128.txt) | 128 | 1 | 250 |  61.28 |   4.89|
| [wyhash-32](raw/wyhash-32.txt) | 32 | 2 | 250 |  31.05 |   1.33|
| [rust-fxhash64.mix](raw/rust-fxhash64.mix.txt) | 64 | 2 | 250 |  38.02 |   4.99|
| [FarmHash-128.CC.seed1](raw/FarmHash-128.CC.seed1.txt) | 128 | 2 | 250 |  69.48 |   4.85|
| [FarmHash-128.CC.seed3](raw/FarmHash-128.CC.seed3.txt) | 128 | 2 | 250 |  70.69 |   4.85|
| [t1ha2-64](raw/t1ha2-64.txt) | 64 | 3 | 250 |  40.44 |   4.62|
| [beamsplitter](raw/beamsplitter.txt) | 64 | 4 | 235 | 920.62 |   0.18|
| [t1ha0.aesA](raw/t1ha0.aesA.txt) | 64 | 5 | 250 |  40.19 |   9.11|
| [t1ha0.aesB](raw/t1ha0.aesB.txt) | 64 | 5 | 250 |  40.43 |  21.42|
| [GoodhartHash4](raw/GoodhartHash4.txt) | 128 | 5 | 250 |  88.87 |   1.32|
| [FarmHash-32.NT](raw/FarmHash-32.NT.txt) | 32 | 6 | 250 |  51.91 |   7.78|
| [SpookyHash1-64](raw/SpookyHash1-64.txt) | 64 | 6 | 250 |  58.84 |   4.41|
| [SpookyHash2-64](raw/SpookyHash2-64.txt) | 64 | 6 | 250 |  60.20 |   4.40|
| [falkhash2](raw/falkhash2.txt) | 128 | 6 | 250 |  85.87 |  18.43|
| [rust-fxhash64.mult32.mix](raw/rust-fxhash64.mult32.mix.txt) | 64 | 7 | 250 |  38.76 |   3.94|
| [polymurhash-tweakseed](raw/polymurhash-tweakseed.txt) | 64 | 7 | 250 |  41.89 |   4.02|
| [CityHashCrc-128.seed3](raw/CityHashCrc-128.seed3.txt) | 128 | 7 | 250 |  70.19 |   5.98|
| [CityHashCrc-128.seed1](raw/CityHashCrc-128.seed1.txt) | 128 | 7 | 250 |  70.24 |   6.00|
| [rust-ahash.noshuf](raw/rust-ahash.noshuf.txt) | 64 | 7 | 250 |  74.39 |   0.66|
| [FarmHash-128.CM.seed2](raw/FarmHash-128.CM.seed2.txt) | 128 | 8 | 250 |  69.54 |   2.61|
| [rust-ahash](raw/rust-ahash.txt) | 64 | 8 | 250 |  69.80 |   2.51|
| [XXH-64](raw/XXH-64.txt) | 64 | 9 | 250 |  52.60 |   3.99|
| [FarmHash-128.CC.seed2](raw/FarmHash-128.CC.seed2.txt) | 128 | 10 | 250 |  69.57 |   4.85|
| [falkhash1](raw/falkhash1.txt) | 128 | 10 | 250 |  83.97 |  19.88|
| [perl-stadtx](raw/perl-stadtx.txt) | 64 | 11 | 250 |  38.51 |   4.72|
| [perl-zaphod32](raw/perl-zaphod32.txt) | 32 | 12 | 250 |  39.48 |   1.30|
| [CityHashCrc-128.seed2](raw/CityHashCrc-128.seed2.txt) | 128 | 13 | 250 |  70.86 |   6.00|
| [rust-fxhash32.mix](raw/rust-fxhash32.mix.txt) | 32 | 14 | 250 |  40.91 |   3.94|
| [TinySipHash](raw/TinySipHash.txt) | 64 | 14 | 250 |  41.71 |   1.50|
| [SpookyHash1-128](raw/SpookyHash1-128.txt) | 128 | 14 | 250 |  63.26 |   4.40|
| [wyhash](raw/wyhash.txt) | 64 | 15 | 250 |  29.31 |   6.98|
| [XXH3-64.regen](raw/XXH3-64.regen.txt) | 64 | 15 | 250 |  29.98 |  12.85|
| [mulxp1-hash](raw/mulxp1-hash.txt) | 64 | 15 | 250 |  30.12 |   2.86|
| [wyhash.strict](raw/wyhash.strict.txt) | 64 | 15 | 250 |  31.49 |   5.79|
| [SpookyHash2-128](raw/SpookyHash2-128.txt) | 128 | 15 | 250 |  64.52 |   4.40|
| [pengyhash](raw/pengyhash.txt) | 64 | 16 | 250 |  89.81 |   3.80|
| [mum1.inexact.unroll2](raw/mum1.inexact.unroll2.txt) | 64 | 17 | 250 |  46.60 |   1.21|
| [mum1.inexact.unroll3](raw/mum1.inexact.unroll3.txt) | 64 | 17 | 250 |  46.87 |   1.33|
| [mum1.inexact.unroll4](raw/mum1.inexact.unroll4.txt) | 64 | 17 | 250 |  46.96 |   1.87|
| [mir.inexact](raw/mir.inexact.txt) | 64 | 17 | 250 |  48.62 |   1.33|
| [mum1.inexact.unroll1](raw/mum1.inexact.unroll1.txt) | 64 | 17 | 250 |  50.31 |   1.15|
| [MetroHash-128](raw/MetroHash-128.txt) | 128 | 17 | 250 |  52.90 |   5.02|
| [floppsyhash](raw/floppsyhash.txt) | 64 | 17 | 235 | 724.92 |   0.05|
| [mulxp3-hash](raw/mulxp3-hash.txt) | 64 | 18 | 250 |  27.89 |   4.99|
| [mum1.exact.unroll4](raw/mum1.exact.unroll4.txt) | 64 | 18 | 250 |  34.36 |   3.95|
| [mum1.exact.unroll3](raw/mum1.exact.unroll3.txt) | 64 | 18 | 250 |  34.38 |   4.37|
| [mum1.exact.unroll2](raw/mum1.exact.unroll2.txt) | 64 | 18 | 250 |  34.79 |   4.12|
| [mum1.exact.unroll1](raw/mum1.exact.unroll1.txt) | 64 | 18 | 250 |  36.67 |   2.57|
| [mir.exact](raw/mir.exact.txt) | 64 | 18 | 250 |  37.80 |   2.20|
| [t1ha0](raw/t1ha0.txt) | 64 | 18 | 250 |  45.35 |   2.42|
| [t1ha2-64.incr](raw/t1ha2-64.incr.txt) | 64 | 18 | 250 |  78.10 |   4.87|
| [XXH3-128.regen](raw/XXH3-128.regen.txt) | 128 | 19 | 250 |  35.48 |  12.74|
| [FARSH-32.tweaked](raw/FARSH-32.tweaked.txt) | 32 | 19 | 250 |  63.86 |  13.78|
| [FARSH-64.tweaked](raw/FARSH-64.tweaked.txt) | 64 | 19 | 250 | 116.34 |   6.96|
| [FARSH-256.tweaked](raw/FARSH-256.tweaked.txt) | 256 | 19 | 235 | 475.90 |   1.74|
| [CityHashCrc-256](raw/CityHashCrc-256.txt) | 256 | 21 | 238 | 183.24 |   6.01|
| [MetroHash-128.var1](raw/MetroHash-128.var1.txt) | 128 | 22 | 250 |  52.91 |   5.01|
| [MetroHash-128.var2](raw/MetroHash-128.var2.txt) | 128 | 22 | 250 |  52.99 |   5.02|
| [CLhash.bitmix](raw/CLhash.bitmix.txt) | 64 | 23 | 250 |  60.80 |   7.33|
| [t1ha2-128.incr](raw/t1ha2-128.incr.txt) | 128 | 23 | 250 | 104.53 |   4.87|
| [FARSH-128.tweaked](raw/FARSH-128.tweaked.txt) | 128 | 23 | 238 | 234.44 |   3.48|
| [gxhash-64](raw/gxhash-64.txt) | 64 | 24 | 250 |  37.35 |  19.14|
| [mum3.exact.unroll1](raw/mum3.exact.unroll1.txt) | 64 | 25 | 250 |  29.63 |   2.65|
| [gxhash](raw/gxhash.txt) | 128 | 25 | 250 |  37.26 |  19.56|
| [XXH3-64](raw/XXH3-64.txt) | 64 | 27 | 250 |  30.69 |  12.82|
| [MetroHash-64](raw/MetroHash-64.txt) | 64 | 29 | 250 |  42.39 |   5.00|
| [MetroHash-64.var2](raw/MetroHash-64.var2.txt) | 64 | 29 | 250 |  42.49 |   5.02|
| [tabulation-64](raw/tabulation-64.txt) | 64 | 30 | 250 |  37.33 |   3.12|
| [mum3.exact.unroll2](raw/mum3.exact.unroll2.txt) | 64 | 33 | 250 |  27.31 |   5.07|
| [MetroHash-64.var1](raw/MetroHash-64.var1.txt) | 64 | 33 | 250 |  42.39 |   4.99|
| [poly-mersenne.deg2](raw/poly-mersenne.deg2.txt) | 32 | 34 | 238 |  61.56 |   0.50|
| [mum3.exact.unroll3](raw/mum3.exact.unroll3.txt) | 64 | 36 | 250 |  27.39 |   5.97|
| [mum3.exact.unroll4](raw/mum3.exact.unroll4.txt) | 64 | 36 | 250 |  28.06 |   5.86|
| [XXH3-128](raw/XXH3-128.txt) | 128 | 36 | 250 |  36.13 |  12.72|
| [UMASH-64.reseed](raw/UMASH-64.reseed.txt) | 64 | 36 | 250 |  41.90 |   6.09|
| [mx3.v3](raw/mx3.v3.txt) | 64 | 36 | 250 |  49.38 |   3.76|
| [mx3.v2](raw/mx3.v2.txt) | 64 | 36 | 250 |  51.59 |   3.21|
| [HalftimeHash-64](raw/HalftimeHash-64.txt) | 64 | 36 | 250 |  83.75 |   2.02|
| [UMASH-128.reseed](raw/UMASH-128.reseed.txt) | 128 | 37 | 250 |  44.95 |   3.79|
| [FarmHash-64.UO](raw/FarmHash-64.UO.txt) | 64 | 37 | 250 |  51.54 |   5.09|
| [FarmHash-64.TE](raw/FarmHash-64.TE.txt) | 64 | 37 | 250 |  51.87 |   7.78|
| [aesnihash-peterrk](raw/aesnihash-peterrk.txt) | 128 | 41 | 250 |  32.58 |   9.43|
| [FarmHash-32.MK](raw/FarmHash-32.MK.txt) | 32 | 42 | 250 |  42.82 |   1.53|
| [mum2.exact.unroll1](raw/mum2.exact.unroll1.txt) | 64 | 45 | 250 |  32.48 |   2.58|
| [mum2.inexact.unroll1](raw/mum2.inexact.unroll1.txt) | 64 | 45 | 250 |  42.68 |   1.14|
| [mx3.v1](raw/mx3.v1.txt) | 64 | 45 | 250 |  49.48 |   3.21|
| [FarmHash-64.NA](raw/FarmHash-64.NA.txt) | 64 | 45 | 250 |  51.35 |   4.69|
| [CityHash-64](raw/CityHash-64.txt) | 64 | 45 | 250 |  51.89 |   4.75|
| [seahash](raw/seahash.txt) | 64 | 45 | 250 |  55.06 |   2.67|
| [MetroHashCrc-64.var1](raw/MetroHashCrc-64.var1.txt) | 64 | 46 | 250 |  46.53 |   7.98|
| [MetroHashCrc-64.var2](raw/MetroHashCrc-64.var2.txt) | 64 | 47 | 250 |  46.50 |   7.92|
| [HalftimeHash-128](raw/HalftimeHash-128.txt) | 64 | 48 | 250 |  95.58 |   6.87|
| [FarmHash-32.SA](raw/FarmHash-32.SA.txt) | 32 | 50 | 250 |  42.49 |   5.00|
| [FarmHash-32.CC](raw/FarmHash-32.CC.txt) | 32 | 50 | 250 |  42.65 |   1.92|
| [MetroHashCrc-128.var1](raw/MetroHashCrc-128.var1.txt) | 128 | 50 | 250 |  58.38 |   7.98|
| [MetroHashCrc-128.var2](raw/MetroHashCrc-128.var2.txt) | 128 | 50 | 250 |  58.38 |   7.96|
| [HalftimeHash-256](raw/HalftimeHash-256.txt) | 64 | 50 | 250 | 100.89 |  11.70|
| [FarmHash-32.SU](raw/FarmHash-32.SU.txt) | 32 | 51 | 250 |  42.49 |   5.99|
| [AquaHash](raw/AquaHash.txt) | 128 | 55 | 250 |  34.31 |  15.84|
| [VHASH.32](raw/VHASH.32.txt) | 32 | 56 | 250 |  91.32 |   5.12|
| [fasthash-32](raw/fasthash-32.txt) | 32 | 59 | 250 |  41.45 |   2.00|
| [mulxp3-hash32](raw/mulxp3-hash32.txt) | 32 | 60 | 250 |  27.84 |   5.07|
| [VHASH](raw/VHASH.txt) | 64 | 60 | 250 |  91.31 |   5.14|
| [HalftimeHash-512](raw/HalftimeHash-512.txt) | 64 | 60 | 250 | 113.77 |   9.51|
| [mum2.exact.unroll2](raw/mum2.exact.unroll2.txt) | 64 | 62 | 250 |  30.50 |   4.13|
| [mum2.inexact.unroll2](raw/mum2.inexact.unroll2.txt) | 64 | 63 | 250 |  38.39 |   1.26|
| [t1ha1](raw/t1ha1.txt) | 64 | 65 | 250 |  30.31 |   4.58|
| [mum2.exact.unroll3](raw/mum2.exact.unroll3.txt) | 64 | 70 | 250 |  30.46 |   4.37|
| [CityHash-32](raw/CityHash-32.txt) | 32 | 70 | 250 |  44.19 |   1.92|
| [mum2.inexact.unroll3](raw/mum2.inexact.unroll3.txt) | 64 | 71 | 250 |  38.46 |   1.33|
| [perl-zaphod32.sbox128.old](raw/perl-zaphod32.sbox128.old.txt) | 32 | 75 | 250 |  27.21 |   1.31|
| [perl-zaphod32.sbox96](raw/perl-zaphod32.sbox96.txt) | 32 | 75 | 250 |  27.30 |   1.31|
| [perl-zaphod32.sbox128](raw/perl-zaphod32.sbox128.txt) | 32 | 76 | 250 |  27.20 |   1.31|
| [mum2.exact.unroll4](raw/mum2.exact.unroll4.txt) | 64 | 77 | 250 |  29.98 |   4.01|
| [mum2.inexact.unroll4](raw/mum2.inexact.unroll4.txt) | 64 | 78 | 250 |  38.88 |   1.87|
| [NMHASH](raw/NMHASH.txt) | 32 | 78 | 250 |  52.79 |   7.71|
| [MurmurHash3-32](raw/MurmurHash3-32.txt) | 32 | 82 | 250 |  44.83 |   1.00|
| [GoodhartHash2](raw/GoodhartHash2.txt) | 128 | 82 | 250 |  75.46 |   5.33|
| [XXH-32](raw/XXH-32.txt) | 32 | 83 | 250 |  44.38 |   2.00|
| [mulxp1-hash32](raw/mulxp1-hash32.txt) | 32 | 87 | 250 |  28.88 |   7.82|
| [MurmurHash3-128](raw/MurmurHash3-128.txt) | 128 | 87 | 250 |  47.59 |   2.36|
| [lookup3.32](raw/lookup3.32.txt) | 32 | 91 | 238 |  35.99 |   0.81|
| [floppsyhash.old](raw/floppsyhash.old.txt) | 64 | 94 | 235 | 698.79 |   0.04|
| [MurmurHash3-128.int32](raw/MurmurHash3-128.int32.txt) | 128 | 96 | 250 |  46.82 |   1.63|
| [mum3.inexact.unroll1](raw/mum3.inexact.unroll1.txt) | 64 | 98 | 250 |  38.52 |   1.39|
| [fasthash-64](raw/fasthash-64.txt) | 64 | 99 | 250 |  39.66 |   2.00|
| [NMHASHX](raw/NMHASHX.txt) | 32 | 100 | 250 |  39.77 |   7.72|
| [MurmurHash2-64](raw/MurmurHash2-64.txt) | 64 | 101 | 250 |  39.95 |   2.00|
| [tabulation-32](raw/tabulation-32.txt) | 32 | 103 | 250 |  27.88 |   2.20|
| [mum3.inexact.unroll2](raw/mum3.inexact.unroll2.txt) | 64 | 116 | 250 |  33.78 |   1.81|
| [MurmurHash1](raw/MurmurHash1.txt) | 32 | 116 | 238 |  46.29 |   0.67|
| [lookup3](raw/lookup3.txt) | 64 | 122 | 238 |  36.01 |   0.81|
| [mum3.inexact.unroll3](raw/mum3.inexact.unroll3.txt) | 64 | 126 | 250 |  34.37 |   2.02|
| [UMASH-64](raw/UMASH-64.txt) | 64 | 127 | 250 |  41.73 |   6.09|
| [UMASH-128](raw/UMASH-128.txt) | 128 | 128 | 250 |  45.18 |   3.82|
| [rust-rapidhash.p.fast.seed](raw/rust-rapidhash.p.fast.seed.txt) | 64 | 131 | 250 |  28.62 |   3.07|
| [rust-rapidhash.p.fast](raw/rust-rapidhash.p.fast.txt) | 64 | 131 | 250 |  28.86 |   3.07|
| [rust-rapidhash.fast.seed](raw/rust-rapidhash.fast.seed.txt) | 64 | 132 | 250 |  24.38 |   8.67|
| [rust-rapidhash.fast](raw/rust-rapidhash.fast.txt) | 64 | 132 | 250 |  24.46 |   8.67|
| [mum3.inexact.unroll4](raw/mum3.inexact.unroll4.txt) | 64 | 132 | 250 |  35.17 |   1.97|
| [poly-mersenne.deg1](raw/poly-mersenne.deg1.txt) | 32 | 134 | 238 |  53.30 |   0.50|
| [perl-jenkins-hard](raw/perl-jenkins-hard.txt) | 32 | 134 | 235 | 115.01 |   0.20|
| [MurmurHash2a](raw/MurmurHash2a.txt) | 32 | 150 | 250 |  43.77 |   1.00|
| [Crap8](raw/Crap8.txt) | 32 | 161 | 250 |  34.04 |   1.00|
| [poly-mersenne.deg0](raw/poly-mersenne.deg0.txt) | 32 | 161 | 238 |  45.22 |   0.49|
| [Abseil64-city](raw/Abseil64-city.txt) | 64 | 162 | 250 |  22.35 |   4.04|
| [perl-jenkins](raw/perl-jenkins.txt) | 32 | 164 | 235 |  95.00 |   0.20|
| [rust-fxhash64](raw/rust-fxhash64.txt) | 64 | 165 | 250 |  30.02 |   4.99|
| [MurmurHash2-32](raw/MurmurHash2-32.txt) | 32 | 173 | 250 |  38.94 |   1.00|
| [rust-fxhash32](raw/rust-fxhash32.txt) | 32 | 186 | 250 |  34.94 |   3.94|
| [CLhash](raw/CLhash.txt) | 64 | 186 | 250 |  48.19 |   7.36|
| [Abseil64-llh](raw/Abseil64-llh.txt) | 64 | 191 | 250 |  21.96 |   7.42|
| [FNV-Mulvey](raw/FNV-Mulvey.txt) | 32 | 194 | 235 |  83.01 |   0.25|
| [MicroOAAT](raw/MicroOAAT.txt) | 32 | 195 | 235 |  76.56 |   0.23|
| [MurmurHash2-64.int32](raw/MurmurHash2-64.int32.txt) | 64 | 208 | 250 |  44.57 |   1.33|
| [rust-fxhash64.mult32](raw/rust-fxhash64.mult32.txt) | 64 | 214 | 250 |  31.14 |   3.94|
| [SuperFastHash](raw/SuperFastHash.txt) | 32 | 219 | 238 |  45.12 |   0.78|
| [Pearson-64](raw/Pearson-64.txt) | 64 | 219 | 235 | 125.08 |   0.14|
| [Pearson-256](raw/Pearson-256.txt) | 256 | 220 | 235 | 126.13 |   0.14|
| [Pearson-128](raw/Pearson-128.txt) | 128 | 222 | 235 | 121.01 |   0.14|
| [pair-multiply-shift-32](raw/pair-multiply-shift-32.txt) | 32 | 226 | 250 |  23.26 |   2.24|
| [Abseil32](raw/Abseil32.txt) | 64 | 226 | 250 |  42.94 |   1.84|
| [FNV-1a-32](raw/FNV-1a-32.txt) | 32 | 227 | 235 |  73.02 |   0.25|
| [multiply-shift-32](raw/multiply-shift-32.txt) | 32 | 230 | 250 |  18.61 |   1.51|
| [FNV-YoshimitsuTRIAD](raw/FNV-YoshimitsuTRIAD.txt) | 32 | 230 | 250 |  26.17 |   5.27|
| [pair-multiply-shift](raw/pair-multiply-shift.txt) | 64 | 230 | 250 |  26.68 |   1.89|
| [perl-djb2](raw/perl-djb2.txt) | 32 | 230 | 235 |  55.03 |   0.33|
| [perl-sdbm](raw/perl-sdbm.txt) | 32 | 230 | 235 |  70.00 |   0.25|
| [FNV-1a-64](raw/FNV-1a-64.txt) | 64 | 230 | 235 |  73.00 |   0.25|
| [x17](raw/x17.txt) | 32 | 230 | 235 |  73.12 |   0.25|
| [FNV-1a-128](raw/FNV-1a-128.txt) | 128 | 230 | 235 |  93.08 |   0.19|
| [multiply-shift](raw/multiply-shift.txt) | 64 | 232 | 250 |  25.01 |   1.79|
| [CRC-32C](raw/CRC-32C.txt) | 32 | 235 | 250 |  30.75 |   7.69|
| [Fletcher-32](raw/Fletcher-32.txt) | 32 | 239 | 250 |  33.04 |   1.45|
| [Fletcher-64](raw/Fletcher-64.txt) | 64 | 242 | 250 |  33.27 |   2.00|


Hashes that pass Sanity tests, but fail others, sorted by average short input speed and then failing tests.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [multiply-shift-32](raw/multiply-shift-32.txt) | 32 | 230 | 250 |  18.61 |   1.51|
| [Abseil64-llh](raw/Abseil64-llh.txt) | 64 | 191 | 250 |  21.96 |   7.42|
| [Abseil64-city](raw/Abseil64-city.txt) | 64 | 162 | 250 |  22.35 |   4.04|
| [pair-multiply-shift-32](raw/pair-multiply-shift-32.txt) | 32 | 226 | 250 |  23.26 |   2.24|
| [rust-rapidhash.fast.seed](raw/rust-rapidhash.fast.seed.txt) | 64 | 132 | 250 |  24.38 |   8.67|
| [rust-rapidhash.fast](raw/rust-rapidhash.fast.txt) | 64 | 132 | 250 |  24.46 |   8.67|
| [multiply-shift](raw/multiply-shift.txt) | 64 | 232 | 250 |  25.01 |   1.79|
| [FNV-YoshimitsuTRIAD](raw/FNV-YoshimitsuTRIAD.txt) | 32 | 230 | 250 |  26.17 |   5.27|
| [pair-multiply-shift](raw/pair-multiply-shift.txt) | 64 | 230 | 250 |  26.68 |   1.89|
| [perl-zaphod32.sbox128](raw/perl-zaphod32.sbox128.txt) | 32 | 76 | 250 |  27.20 |   1.31|
| [perl-zaphod32.sbox128.old](raw/perl-zaphod32.sbox128.old.txt) | 32 | 75 | 250 |  27.21 |   1.31|
| [perl-zaphod32.sbox96](raw/perl-zaphod32.sbox96.txt) | 32 | 75 | 250 |  27.30 |   1.31|
| [mum3.exact.unroll2](raw/mum3.exact.unroll2.txt) | 64 | 33 | 250 |  27.31 |   5.07|
| [mum3.exact.unroll3](raw/mum3.exact.unroll3.txt) | 64 | 36 | 250 |  27.39 |   5.97|
| [mulxp3-hash32](raw/mulxp3-hash32.txt) | 32 | 60 | 250 |  27.84 |   5.07|
| [tabulation-32](raw/tabulation-32.txt) | 32 | 103 | 250 |  27.88 |   2.20|
| [mulxp3-hash](raw/mulxp3-hash.txt) | 64 | 18 | 250 |  27.89 |   4.99|
| [mum3.exact.unroll4](raw/mum3.exact.unroll4.txt) | 64 | 36 | 250 |  28.06 |   5.86|
| [rust-rapidhash.p.fast.seed](raw/rust-rapidhash.p.fast.seed.txt) | 64 | 131 | 250 |  28.62 |   3.07|
| [rust-rapidhash.p.fast](raw/rust-rapidhash.p.fast.txt) | 64 | 131 | 250 |  28.86 |   3.07|
| [mulxp1-hash32](raw/mulxp1-hash32.txt) | 32 | 87 | 250 |  28.88 |   7.82|
| [wyhash](raw/wyhash.txt) | 64 | 15 | 250 |  29.31 |   6.98|
| [w1hash](raw/w1hash.txt) | 64 | 1 | 250 |  29.34 |   8.15|
| [mum3.exact.unroll1](raw/mum3.exact.unroll1.txt) | 64 | 25 | 250 |  29.63 |   2.65|
| [XXH3-64.regen](raw/XXH3-64.regen.txt) | 64 | 15 | 250 |  29.98 |  12.85|
| [mum2.exact.unroll4](raw/mum2.exact.unroll4.txt) | 64 | 77 | 250 |  29.98 |   4.01|
| [rust-fxhash64](raw/rust-fxhash64.txt) | 64 | 165 | 250 |  30.02 |   4.99|
| [mulxp1-hash](raw/mulxp1-hash.txt) | 64 | 15 | 250 |  30.12 |   2.86|
| [t1ha1](raw/t1ha1.txt) | 64 | 65 | 250 |  30.31 |   4.58|
| [mum2.exact.unroll3](raw/mum2.exact.unroll3.txt) | 64 | 70 | 250 |  30.46 |   4.37|
| [mum2.exact.unroll2](raw/mum2.exact.unroll2.txt) | 64 | 62 | 250 |  30.50 |   4.13|
| [XXH3-64](raw/XXH3-64.txt) | 64 | 27 | 250 |  30.69 |  12.82|
| [CRC-32C](raw/CRC-32C.txt) | 32 | 235 | 250 |  30.75 |   7.69|
| [wyhash-32](raw/wyhash-32.txt) | 32 | 2 | 250 |  31.05 |   1.33|
| [rust-fxhash64.mult32](raw/rust-fxhash64.mult32.txt) | 64 | 214 | 250 |  31.14 |   3.94|
| [wyhash.strict](raw/wyhash.strict.txt) | 64 | 15 | 250 |  31.49 |   5.79|
| [mum2.exact.unroll1](raw/mum2.exact.unroll1.txt) | 64 | 45 | 250 |  32.48 |   2.58|
| [aesnihash-peterrk](raw/aesnihash-peterrk.txt) | 128 | 41 | 250 |  32.58 |   9.43|
| [Fletcher-32](raw/Fletcher-32.txt) | 32 | 239 | 250 |  33.04 |   1.45|
| [Fletcher-64](raw/Fletcher-64.txt) | 64 | 242 | 250 |  33.27 |   2.00|
| [mum3.inexact.unroll2](raw/mum3.inexact.unroll2.txt) | 64 | 116 | 250 |  33.78 |   1.81|
| [Crap8](raw/Crap8.txt) | 32 | 161 | 250 |  34.04 |   1.00|
| [AquaHash](raw/AquaHash.txt) | 128 | 55 | 250 |  34.31 |  15.84|
| [mum1.exact.unroll4](raw/mum1.exact.unroll4.txt) | 64 | 18 | 250 |  34.36 |   3.95|
| [mum3.inexact.unroll3](raw/mum3.inexact.unroll3.txt) | 64 | 126 | 250 |  34.37 |   2.02|
| [mum1.exact.unroll3](raw/mum1.exact.unroll3.txt) | 64 | 18 | 250 |  34.38 |   4.37|
| [mum1.exact.unroll2](raw/mum1.exact.unroll2.txt) | 64 | 18 | 250 |  34.79 |   4.12|
| [rust-fxhash32](raw/rust-fxhash32.txt) | 32 | 186 | 250 |  34.94 |   3.94|
| [mum3.inexact.unroll4](raw/mum3.inexact.unroll4.txt) | 64 | 132 | 250 |  35.17 |   1.97|
| [XXH3-128.regen](raw/XXH3-128.regen.txt) | 128 | 19 | 250 |  35.48 |  12.74|
| [lookup3.32](raw/lookup3.32.txt) | 32 | 91 | 238 |  35.99 |   0.81|
| [lookup3](raw/lookup3.txt) | 64 | 122 | 238 |  36.01 |   0.81|
| [XXH3-128](raw/XXH3-128.txt) | 128 | 36 | 250 |  36.13 |  12.72|
| [mum1.exact.unroll1](raw/mum1.exact.unroll1.txt) | 64 | 18 | 250 |  36.67 |   2.57|
| [gxhash](raw/gxhash.txt) | 128 | 25 | 250 |  37.26 |  19.56|
| [tabulation-64](raw/tabulation-64.txt) | 64 | 30 | 250 |  37.33 |   3.12|
| [gxhash-64](raw/gxhash-64.txt) | 64 | 24 | 250 |  37.35 |  19.14|
| [mir.exact](raw/mir.exact.txt) | 64 | 18 | 250 |  37.80 |   2.20|
| [rust-fxhash64.mix](raw/rust-fxhash64.mix.txt) | 64 | 2 | 250 |  38.02 |   4.99|
| [mum2.inexact.unroll2](raw/mum2.inexact.unroll2.txt) | 64 | 63 | 250 |  38.39 |   1.26|
| [mum2.inexact.unroll3](raw/mum2.inexact.unroll3.txt) | 64 | 71 | 250 |  38.46 |   1.33|
| [perl-stadtx](raw/perl-stadtx.txt) | 64 | 11 | 250 |  38.51 |   4.72|
| [mum3.inexact.unroll1](raw/mum3.inexact.unroll1.txt) | 64 | 98 | 250 |  38.52 |   1.39|
| [rust-fxhash64.mult32.mix](raw/rust-fxhash64.mult32.mix.txt) | 64 | 7 | 250 |  38.76 |   3.94|
| [mum2.inexact.unroll4](raw/mum2.inexact.unroll4.txt) | 64 | 78 | 250 |  38.88 |   1.87|
| [MurmurHash2-32](raw/MurmurHash2-32.txt) | 32 | 173 | 250 |  38.94 |   1.00|
| [perl-zaphod32](raw/perl-zaphod32.txt) | 32 | 12 | 250 |  39.48 |   1.30|
| [fasthash-64](raw/fasthash-64.txt) | 64 | 99 | 250 |  39.66 |   2.00|
| [NMHASHX](raw/NMHASHX.txt) | 32 | 100 | 250 |  39.77 |   7.72|
| [MurmurHash2-64](raw/MurmurHash2-64.txt) | 64 | 101 | 250 |  39.95 |   2.00|
| [t1ha0.aesA](raw/t1ha0.aesA.txt) | 64 | 5 | 250 |  40.19 |   9.11|
| [t1ha0.aesB](raw/t1ha0.aesB.txt) | 64 | 5 | 250 |  40.43 |  21.42|
| [t1ha2-64](raw/t1ha2-64.txt) | 64 | 3 | 250 |  40.44 |   4.62|
| [rust-fxhash32.mix](raw/rust-fxhash32.mix.txt) | 32 | 14 | 250 |  40.91 |   3.94|
| [fasthash-32](raw/fasthash-32.txt) | 32 | 59 | 250 |  41.45 |   2.00|
| [TinySipHash](raw/TinySipHash.txt) | 64 | 14 | 250 |  41.71 |   1.50|
| [UMASH-64](raw/UMASH-64.txt) | 64 | 127 | 250 |  41.73 |   6.09|
| [polymurhash-tweakseed](raw/polymurhash-tweakseed.txt) | 64 | 7 | 250 |  41.89 |   4.02|
| [UMASH-64.reseed](raw/UMASH-64.reseed.txt) | 64 | 36 | 250 |  41.90 |   6.09|
| [MetroHash-64](raw/MetroHash-64.txt) | 64 | 29 | 250 |  42.39 |   5.00|
| [MetroHash-64.var1](raw/MetroHash-64.var1.txt) | 64 | 33 | 250 |  42.39 |   4.99|
| [MetroHash-64.var2](raw/MetroHash-64.var2.txt) | 64 | 29 | 250 |  42.49 |   5.02|
| [FarmHash-32.SA](raw/FarmHash-32.SA.txt) | 32 | 50 | 250 |  42.49 |   5.00|
| [FarmHash-32.SU](raw/FarmHash-32.SU.txt) | 32 | 51 | 250 |  42.49 |   5.99|
| [FarmHash-32.CC](raw/FarmHash-32.CC.txt) | 32 | 50 | 250 |  42.65 |   1.92|
| [mum2.inexact.unroll1](raw/mum2.inexact.unroll1.txt) | 64 | 45 | 250 |  42.68 |   1.14|
| [FarmHash-32.MK](raw/FarmHash-32.MK.txt) | 32 | 42 | 250 |  42.82 |   1.53|
| [Abseil32](raw/Abseil32.txt) | 64 | 226 | 250 |  42.94 |   1.84|
| [MurmurHash2a](raw/MurmurHash2a.txt) | 32 | 150 | 250 |  43.77 |   1.00|
| [CityHash-32](raw/CityHash-32.txt) | 32 | 70 | 250 |  44.19 |   1.92|
| [XXH-32](raw/XXH-32.txt) | 32 | 83 | 250 |  44.38 |   2.00|
| [MurmurHash2-64.int32](raw/MurmurHash2-64.int32.txt) | 64 | 208 | 250 |  44.57 |   1.33|
| [MurmurHash3-32](raw/MurmurHash3-32.txt) | 32 | 82 | 250 |  44.83 |   1.00|
| [UMASH-128.reseed](raw/UMASH-128.reseed.txt) | 128 | 37 | 250 |  44.95 |   3.79|
| [SuperFastHash](raw/SuperFastHash.txt) | 32 | 219 | 238 |  45.12 |   0.78|
| [UMASH-128](raw/UMASH-128.txt) | 128 | 128 | 250 |  45.18 |   3.82|
| [poly-mersenne.deg0](raw/poly-mersenne.deg0.txt) | 32 | 161 | 238 |  45.22 |   0.49|
| [t1ha0](raw/t1ha0.txt) | 64 | 18 | 250 |  45.35 |   2.42|
| [MurmurHash1](raw/MurmurHash1.txt) | 32 | 116 | 238 |  46.29 |   0.67|
| [MetroHashCrc-64.var2](raw/MetroHashCrc-64.var2.txt) | 64 | 47 | 250 |  46.50 |   7.92|
| [MetroHashCrc-64.var1](raw/MetroHashCrc-64.var1.txt) | 64 | 46 | 250 |  46.53 |   7.98|
| [mum1.inexact.unroll2](raw/mum1.inexact.unroll2.txt) | 64 | 17 | 250 |  46.60 |   1.21|
| [MurmurHash3-128.int32](raw/MurmurHash3-128.int32.txt) | 128 | 96 | 250 |  46.82 |   1.63|
| [mum1.inexact.unroll3](raw/mum1.inexact.unroll3.txt) | 64 | 17 | 250 |  46.87 |   1.33|
| [mum1.inexact.unroll4](raw/mum1.inexact.unroll4.txt) | 64 | 17 | 250 |  46.96 |   1.87|
| [MurmurHash3-128](raw/MurmurHash3-128.txt) | 128 | 87 | 250 |  47.59 |   2.36|
| [CLhash](raw/CLhash.txt) | 64 | 186 | 250 |  48.19 |   7.36|
| [mir.inexact](raw/mir.inexact.txt) | 64 | 17 | 250 |  48.62 |   1.33|
| [mx3.v3](raw/mx3.v3.txt) | 64 | 36 | 250 |  49.38 |   3.76|
| [mx3.v1](raw/mx3.v1.txt) | 64 | 45 | 250 |  49.48 |   3.21|
| [mum1.inexact.unroll1](raw/mum1.inexact.unroll1.txt) | 64 | 17 | 250 |  50.31 |   1.15|
| [FarmHash-64.NA](raw/FarmHash-64.NA.txt) | 64 | 45 | 250 |  51.35 |   4.69|
| [FarmHash-64.UO](raw/FarmHash-64.UO.txt) | 64 | 37 | 250 |  51.54 |   5.09|
| [mx3.v2](raw/mx3.v2.txt) | 64 | 36 | 250 |  51.59 |   3.21|
| [FarmHash-64.TE](raw/FarmHash-64.TE.txt) | 64 | 37 | 250 |  51.87 |   7.78|
| [CityHash-64](raw/CityHash-64.txt) | 64 | 45 | 250 |  51.89 |   4.75|
| [FarmHash-32.NT](raw/FarmHash-32.NT.txt) | 32 | 6 | 250 |  51.91 |   7.78|
| [XXH-64](raw/XXH-64.txt) | 64 | 9 | 250 |  52.60 |   3.99|
| [NMHASH](raw/NMHASH.txt) | 32 | 78 | 250 |  52.79 |   7.71|
| [MetroHash-128](raw/MetroHash-128.txt) | 128 | 17 | 250 |  52.90 |   5.02|
| [MetroHash-128.var1](raw/MetroHash-128.var1.txt) | 128 | 22 | 250 |  52.91 |   5.01|
| [MetroHash-128.var2](raw/MetroHash-128.var2.txt) | 128 | 22 | 250 |  52.99 |   5.02|
| [poly-mersenne.deg1](raw/poly-mersenne.deg1.txt) | 32 | 134 | 238 |  53.30 |   0.50|
| [perl-djb2](raw/perl-djb2.txt) | 32 | 230 | 235 |  55.03 |   0.33|
| [seahash](raw/seahash.txt) | 64 | 45 | 250 |  55.06 |   2.67|
| [MetroHashCrc-128.var1](raw/MetroHashCrc-128.var1.txt) | 128 | 50 | 250 |  58.38 |   7.98|
| [MetroHashCrc-128.var2](raw/MetroHashCrc-128.var2.txt) | 128 | 50 | 250 |  58.38 |   7.96|
| [SpookyHash1-64](raw/SpookyHash1-64.txt) | 64 | 6 | 250 |  58.84 |   4.41|
| [SpookyHash2-64](raw/SpookyHash2-64.txt) | 64 | 6 | 250 |  60.20 |   4.40|
| [CLhash.bitmix](raw/CLhash.bitmix.txt) | 64 | 23 | 250 |  60.80 |   7.33|
| [t1ha2-128](raw/t1ha2-128.txt) | 128 | 1 | 250 |  61.28 |   4.89|
| [poly-mersenne.deg2](raw/poly-mersenne.deg2.txt) | 32 | 34 | 238 |  61.56 |   0.50|
| [SpookyHash1-128](raw/SpookyHash1-128.txt) | 128 | 14 | 250 |  63.26 |   4.40|
| [FARSH-32.tweaked](raw/FARSH-32.tweaked.txt) | 32 | 19 | 250 |  63.86 |  13.78|
| [SpookyHash2-128](raw/SpookyHash2-128.txt) | 128 | 15 | 250 |  64.52 |   4.40|
| [FarmHash-128.CC.seed1](raw/FarmHash-128.CC.seed1.txt) | 128 | 2 | 250 |  69.48 |   4.85|
| [FarmHash-128.CM.seed2](raw/FarmHash-128.CM.seed2.txt) | 128 | 8 | 250 |  69.54 |   2.61|
| [FarmHash-128.CC.seed2](raw/FarmHash-128.CC.seed2.txt) | 128 | 10 | 250 |  69.57 |   4.85|
| [rust-ahash](raw/rust-ahash.txt) | 64 | 8 | 250 |  69.80 |   2.51|
| [perl-sdbm](raw/perl-sdbm.txt) | 32 | 230 | 235 |  70.00 |   0.25|
| [CityHashCrc-128.seed3](raw/CityHashCrc-128.seed3.txt) | 128 | 7 | 250 |  70.19 |   5.98|
| [CityHashCrc-128.seed1](raw/CityHashCrc-128.seed1.txt) | 128 | 7 | 250 |  70.24 |   6.00|
| [FarmHash-128.CC.seed3](raw/FarmHash-128.CC.seed3.txt) | 128 | 2 | 250 |  70.69 |   4.85|
| [CityHashCrc-128.seed2](raw/CityHashCrc-128.seed2.txt) | 128 | 13 | 250 |  70.86 |   6.00|
| [FNV-1a-64](raw/FNV-1a-64.txt) | 64 | 230 | 235 |  73.00 |   0.25|
| [FNV-1a-32](raw/FNV-1a-32.txt) | 32 | 227 | 235 |  73.02 |   0.25|
| [x17](raw/x17.txt) | 32 | 230 | 235 |  73.12 |   0.25|
| [rust-ahash.noshuf](raw/rust-ahash.noshuf.txt) | 64 | 7 | 250 |  74.39 |   0.66|
| [GoodhartHash2](raw/GoodhartHash2.txt) | 128 | 82 | 250 |  75.46 |   5.33|
| [MicroOAAT](raw/MicroOAAT.txt) | 32 | 195 | 235 |  76.56 |   0.23|
| [t1ha2-64.incr](raw/t1ha2-64.incr.txt) | 64 | 18 | 250 |  78.10 |   4.87|
| [FNV-Mulvey](raw/FNV-Mulvey.txt) | 32 | 194 | 235 |  83.01 |   0.25|
| [HalftimeHash-64](raw/HalftimeHash-64.txt) | 64 | 36 | 250 |  83.75 |   2.02|
| [falkhash1](raw/falkhash1.txt) | 128 | 10 | 250 |  83.97 |  19.88|
| [falkhash2](raw/falkhash2.txt) | 128 | 6 | 250 |  85.87 |  18.43|
| [GoodhartHash4](raw/GoodhartHash4.txt) | 128 | 5 | 250 |  88.87 |   1.32|
| [pengyhash](raw/pengyhash.txt) | 64 | 16 | 250 |  89.81 |   3.80|
| [VHASH](raw/VHASH.txt) | 64 | 60 | 250 |  91.31 |   5.14|
| [VHASH.32](raw/VHASH.32.txt) | 32 | 56 | 250 |  91.32 |   5.12|
| [FNV-1a-128](raw/FNV-1a-128.txt) | 128 | 230 | 235 |  93.08 |   0.19|
| [perl-jenkins](raw/perl-jenkins.txt) | 32 | 164 | 235 |  95.00 |   0.20|
| [HalftimeHash-128](raw/HalftimeHash-128.txt) | 64 | 48 | 250 |  95.58 |   6.87|
| [HalftimeHash-256](raw/HalftimeHash-256.txt) | 64 | 50 | 250 | 100.89 |  11.70|
| [t1ha2-128.incr](raw/t1ha2-128.incr.txt) | 128 | 23 | 250 | 104.53 |   4.87|
| [HalftimeHash-512](raw/HalftimeHash-512.txt) | 64 | 60 | 250 | 113.77 |   9.51|
| [perl-jenkins-hard](raw/perl-jenkins-hard.txt) | 32 | 134 | 235 | 115.01 |   0.20|
| [FARSH-64.tweaked](raw/FARSH-64.tweaked.txt) | 64 | 19 | 250 | 116.34 |   6.96|
| [Pearson-128](raw/Pearson-128.txt) | 128 | 222 | 235 | 121.01 |   0.14|
| [Pearson-64](raw/Pearson-64.txt) | 64 | 219 | 235 | 125.08 |   0.14|
| [Pearson-256](raw/Pearson-256.txt) | 256 | 220 | 235 | 126.13 |   0.14|
| [CityHashCrc-256](raw/CityHashCrc-256.txt) | 256 | 21 | 238 | 183.24 |   6.01|
| [FARSH-128.tweaked](raw/FARSH-128.tweaked.txt) | 128 | 23 | 238 | 234.44 |   3.48|
| [FARSH-256.tweaked](raw/FARSH-256.tweaked.txt) | 256 | 19 | 235 | 475.90 |   1.74|
| [floppsyhash.old](raw/floppsyhash.old.txt) | 64 | 94 | 235 | 698.79 |   0.04|
| [floppsyhash](raw/floppsyhash.txt) | 64 | 17 | 235 | 724.92 |   0.05|
| [beamsplitter](raw/beamsplitter.txt) | 64 | 4 | 235 | 920.62 |   0.18|

Unusable hashes
---------------

Hashes that fail Sanity tests, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
| [aesrng-32](raw/aesrng-32.txt) | 32 | 2 | 250 |   7.00 | 24213.81|
| [aesrng-64](raw/aesrng-64.txt) | 64 | 2 | 250 |   7.00 | 24348.70|
| [aesrng-128](raw/aesrng-128.txt) | 128 | 2 | 250 |  18.02 | 13146.46|
| [aesrng-160](raw/aesrng-160.txt) | 160 | 2 | 250 |  85.00 | 3043.56|
| [aesrng-224](raw/aesrng-224.txt) | 224 | 2 | 250 |  91.78 | 2739.50|
| [aesrng-256](raw/aesrng-256.txt) | 256 | 2 | 250 |  91.89 | 2772.01|
| [FARSH-32](raw/FARSH-32.txt) | 32 | 27 | 250 |  63.73 |  16.09|
| [FARSH-256](raw/FARSH-256.txt) | 256 | 28 | 235 | 477.36 |   1.99|
| [hasshe2](raw/hasshe2.txt) | 256 | 29 | 238 |  96.90 |   0.93|
| [FARSH-64](raw/FARSH-64.txt) | 64 | 30 | 250 | 115.98 |   7.97|
| [FARSH-128](raw/FARSH-128.txt) | 128 | 33 | 238 | 234.02 |   3.98|
| [XXH3-64.reinit](raw/XXH3-64.reinit.txt) | 64 | 52 | 250 |  29.99 |  12.85|
| [XXH3-128.reinit](raw/XXH3-128.reinit.txt) | 128 | 54 | 250 |  35.48 |  12.74|
| [aesnihash-majek](raw/aesnihash-majek.txt) | 64 | 64 | 250 |  57.97 |   1.78|
| [GoodhartHash1](raw/GoodhartHash1.txt) | 128 | 96 | 250 |  73.28 |   5.33|
| [CrapWow-64](raw/CrapWow-64.txt) | 64 | 137 | 250 |  30.93 |   4.74|
| [khash-64](raw/khash-64.txt) | 64 | 143 | 250 |  41.70 |   1.56|
| [MurmurOAAT](raw/MurmurOAAT.txt) | 32 | 165 | 235 | 105.00 |   0.17|
| [CrapWow](raw/CrapWow.txt) | 32 | 166 | 250 |  25.10 |   2.58|
| [perl-jenkins-old](raw/perl-jenkins-old.txt) | 32 | 173 | 235 |  95.00 |   0.20|
| [khash-32](raw/khash-32.txt) | 32 | 181 | 250 |  52.98 |   1.39|
| [FNV-PippipYurii](raw/FNV-PippipYurii.txt) | 32 | 197 | 250 |  31.42 |   2.00|
| [FNV-Totenschiff](raw/FNV-Totenschiff.txt) | 32 | 206 | 250 |  30.06 |   2.00|
| [jodyhash-32](raw/jodyhash-32.txt) | 32 | 221 | 238 |  38.37 |   0.57|
| [badhash](raw/badhash.txt) | 32 | 226 | 235 |  75.95 |   0.23|
| [jodyhash-64](raw/jodyhash-64.txt) | 64 | 230 | 250 |  29.24 |   1.98|
| [FNV-1a-64.wordwise](raw/FNV-1a-64.wordwise.txt) | 64 | 240 | 250 |  34.84 |   2.00|
| [FNV-1a-32.wordwise](raw/FNV-1a-32.wordwise.txt) | 32 | 242 | 250 |  29.69 |   1.00|
| [fletcher2](raw/fletcher2.txt) | 128 | 244 | 250 |  24.01 |   4.93|
| [fletcher2.64](raw/fletcher2.64.txt) | 64 | 245 | 250 |  21.23 |   4.92|
| [fibonacci-64](raw/fibonacci-64.txt) | 64 | 246 | 250 |  22.58 |   9.56|
| [sum32hash](raw/sum32hash.txt) | 32 | 247 | 250 |  14.74 |  25.83|
| [fibonacci-32](raw/fibonacci-32.txt) | 32 | 247 | 250 |  24.50 |  15.97|
| [fletcher4](raw/fletcher4.txt) | 256 | 247 | 250 |  27.73 |   1.91|
| [sum8hash](raw/sum8hash.txt) | 32 | 247 | 250 |  29.63 |   3.37|
| [o1hash](raw/o1hash.txt) | 64 | 248 | 250 |  15.00 | 140946.80|
| [fletcher4.64](raw/fletcher4.64.txt) | 64 | 248 | 250 |  21.10 |   1.91|
| [donothing-128](raw/donothing-128.txt) | 128 | 249 | 250 |   0.00 | 225261.39|
| [donothing-256](raw/donothing-256.txt) | 256 | 249 | 250 |   0.00 | 229320.44|
| [donothing-32](raw/donothing-32.txt) | 32 | 249 | 250 |   0.00 | 228866.34|
| [donothing-64](raw/donothing-64.txt) | 64 | 249 | 250 |   0.00 | 222144.42|
| [donothingOAAT-128](raw/donothingOAAT-128.txt) | 128 | 249 | 250 |  38.96 |   3.39|
| [donothingOAAT-32](raw/donothingOAAT-32.txt) | 32 | 249 | 250 |  39.10 |   3.41|
| [donothingOAAT-64](raw/donothingOAAT-64.txt) | 64 | 249 | 250 |  39.22 |   3.40|

All results were generated using SMHasher3 20251015-release-5035a923 or 20251112-release-15-fedf16f7
