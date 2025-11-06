#!/bin/bash

BIN=../build/SMHasher3

git describe --dirty --always | egrep dirty > /dev/null
ISCLEAN=$?

set -e
set -o pipefail

if [ ${ISCLEAN} -eq 0 ]; then
    echo "DANGER! git shows the tree as dirty. Refusing to continue."
    exit 20
fi

if [ ! -x ${BIN} ]; then
    echo "Binary at ${BIN} not found."
    exit 30
fi

echo "Recording version..."
${BIN} --version | cut -d" " -f2 | cat VERSION.TXT - | sort -u > .v.txt
mv .v.txt VERSION.TXT
echo "Running VerifyAll..."
${BIN} --test=VerifyAll --verbose > VerifyAll.txt
echo "Running SanityAll..."
${BIN} --test=SanityAll > SanityAll.txt
#Not yet; needs more infrastructure to be automatable
#echo "Running SpeedAll..."
#taskset -c 4 nice -n -20 setarch x86_64 -R ${BIN} --test=SpeedAll > SpeedAll.txt
