#!/bin/bash

set -e
set -o pipefail

TMPDIR=/tmp/release
TAB=`echo -en '\t'`

if [ -d "${TMPDIR}" ]; then
    echo "${TMPDIR} exists";
    exit 1;
fi

mkdir -p ${TMPDIR}

../build/SMHasher3 --list                |
    awk 'NR>4 {printf "%s\t%d\n",$1,$2}' |
    sort > ${TMPDIR}/bits.j

awk 'NF!=12 {next} {r="pass"} $0 ~ /FAIL/ {r="FAIL"} {print $1"\t"r}' SanityAll.txt |
    sort > ${TMPDIR}/sanity.j

egrep '^Overall result:' raw/*.txt  |
    sed 's/\.txt:/:/'               |
    sed 's/^raw\///'                |
    tr '(/)' '   '                  |
    awk -F: '{print $1"\t"$NF}'     |
    awk '{printf "%s\t%s\t%d\t%d\n",$1,$2,$4-$3,$4}' |
    sort > ${TMPDIR}/passfail.j

egrep '^ +[0-9]+-byte keys' raw/*.txt   |
    sed 's/\.txt:/:/'                   |
    sed 's/^raw\///'                    |
    tr '(/:)' '    '                    |
    awk '
                     {  sum[$1]+=$5;  cnt[$1]++; }
        END          { for (h in cnt) {
                           printf "%s\t%6.2f\n", h, sum[h]/cnt[h];
                       }
                     }'             |
    sort > ${TMPDIR}/speed1.j

egrep '^Alignment rnd - ' raw/*.txt |
    sed 's/\.txt:/:/'               |
    sed 's/^raw\///'                |
    tr '(/:)' '    '                |
    awk '(NR%2)==0 {printf "%s\t%6.2f\n", $1,$5}' |
    sort > ${TMPDIR}/speed2.j

join -t"$TAB" ${TMPDIR}/bits.j ${TMPDIR}/sanity.j |
    join -t"$TAB" - ${TMPDIR}/passfail.j          |
    join -t"$TAB" - ${TMPDIR}/speed1.j            |
    join -t"$TAB" - ${TMPDIR}/speed2.j            |
    sort -g -k7                                   |
    awk -F'\t' -vOFS='\t' '{$1=sprintf("[%s](raw/%s.txt)", $1, $1); print}' > ${TMPDIR}/joined.t

cat <<EOF
SMHasher3 results summary
=========================

[[_TOC_]]

Passing hashes
--------------

Hashes that currently pass all tests, sorted by average short input speed.

| Hash name | output width | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-----------:|-------------------------:|------------------------:|
EOF

awk -F'\t' '$3=="pass" && $4=="pass" {print}' ${TMPDIR}/joined.t |
    cut -f 1,2,6-                                                |
    tr '\t' '|'                                                  |
    sed 's/|/ | /g'                                              |
    sed 's/^/| /'                                                |
    sed 's/$/|/'

cat <<EOF


Failing hashes
--------------

Hashes that pass Sanity tests, but fail others, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
EOF

awk -F'\t' '$3=="pass" && $4!="pass" {print}' ${TMPDIR}/joined.t |
    cut -f 1,2,5-                                                |
    sort -s -g -k 3 -k 5                                         |
    tr '\t' '|'                                                  |
    sed 's/|/ | /g'                                              |
    sed 's/^/| /'                                                |
    sed 's/$/|/'

cat <<EOF


Hashes that pass Sanity tests, but fail others, sorted by average short input speed and then failing tests.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
EOF

awk -F'\t' '$3=="pass" && $4!="pass" {print}' ${TMPDIR}/joined.t |
    cut -f 1,2,5-                                                |
    sort -s -g -k 5 -k 3                                         |
    tr '\t' '|'                                                  |
    sed 's/|/ | /g'                                              |
    sed 's/^/| /'                                                |
    sed 's/$/|/'

cat <<EOF

Unusable hashes
---------------

Hashes that fail Sanity tests, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
EOF

awk -F'\t' '$3!="pass"               {print}' ${TMPDIR}/joined.t |
    cut -f 1,2,5-                                                |
    sort -s -g -k 3                                              |
    tr '\t' '|'                                                  |
    sed 's/|/ | /g'                                              |
    sed 's/^/| /'                                                |
    sed 's/$/|/'

VERS=`cat VERSION.TXT | xargs | sed 's/ / or /g'`

cat <<EOF

All results were generated using SMHasher3 $VERS
EOF
