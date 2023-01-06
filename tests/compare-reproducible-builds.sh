#!/bin/sh
set -e

cargo run -- build --reproducible -c test.cage.toml > first-build.json
# shasum gives us <SHA> <FILENAME> so need to extract the first word
FIRST_SHA=`shasum first-build.json | cut -d" " -f1`

cargo run -- build --reproducible -c test.cage.toml > second-build.json
SECOND_SHA=`shasum second-build.json | cut -d" " -f1`

if [ "$FIRST_SHA" = "$SECOND_SHA" ]; then
  echo "PCRs match!"
  exit 0
else
  echo "PCRs aren't equal!"
  echo "$FIRST_SHA $SECOND_SHA"
  diff first-build.json second-build.json
  exit 1
fi