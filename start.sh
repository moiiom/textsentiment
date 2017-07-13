#!/usr/bin/env bash
dir=$(cd "$(dirname "$0")"; pwd)
cd ${dir}

python sentiment_analysis.py > analysis.out 2>&1  &
