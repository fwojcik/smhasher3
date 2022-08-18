#!/bin/bash
TMPDIR=/tmp
TAB=`echo -en '\t'`

../build/SMHasher3 --list           |
    awk '{printf "%s\t%d\n",$1,$2}' |
    sort > ${TMPDIR}/bits.j

awk 'NF!=12 {next} {r="pass"} $0 ~ /FAIL/ {r="FAIL"} {print $1"\t"r}' SanityAll.txt |
    sort > ${TMPDIR}/sanity.j

egrep '^Overall result:' *.txt  |
    sed 's/\.txt:/:/'           |
    tr '(/)' '   '              |
    awk -F: '{print $1"\t"$NF}' |
    awk '{printf "%s\t%s\t%d\t%d\n",$1,$2,$4-$3,$4}' |
    sort > ${TMPDIR}/passfail.j 

awk 'NR>6 && NF==10 {printf "%s\t%6.2f\t%6.2f\n",$1,($3+$5+$7+$9)/4.0,$2}' SpeedAll.txt |
    sort > ${TMPDIR}/speed.j

join -t"$TAB" ${TMPDIR}/bits.j ${TMPDIR}/sanity.j |
    join -t"$TAB" - ${TMPDIR}/passfail.j          |
    join -t"$TAB" - ${TMPDIR}/speed.j             |
    sort -g -k7                                   |
    awk -F'\t' -vOFS='\t' '{$1=sprintf("[%s](%s.txt)", $1, $1); print}' > ${TMPDIR}/joined.t

cat <<EOF
SMHasher3 results summary
=========================

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


Hashes that pass Sanity tests, but fail others, sorted by failing tests and then average short input speed.

| Hash name | output width | tests failed | test count | Avg. cycles (1-32 bytes) | Avg. bytes/cycle (bulk) |
|:----------|-------------:|-------------:|-----------:|-------------------------:|------------------------:|
EOF

awk -F'\t' '$3=="pass" && $4!="pass" {print}' ${TMPDIR}/joined.t |
    cut -f 1,2,5-                                                |
    sort -s -g -k 3                                              |
    tr '\t' '|'                                                  |
    sed 's/|/ | /g'                                              |
    sed 's/^/| /'                                                |
    sed 's/$/|/'

cat <<EOF


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

VERS=`cat VERSION.TXT`

cat <<EOF

All results were generated using: $VERS
EOF
