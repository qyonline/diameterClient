#!/usr/bin/env bash

scrip_dir=$(cd "$(dirname "$0")"; pwd)
cd $scrip_dir

cat pid | while read line
do
    kill -9 $line
done
