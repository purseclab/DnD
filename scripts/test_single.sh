#!/usr/bin/env bash

TARGET=$1
METHOD=$2

python -m unittest tests.test_${TARGET}.Test${TARGET^}.${METHOD}
