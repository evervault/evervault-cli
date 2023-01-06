#!/bin/sh
set -e

FIRST_PCRS=`cargo run -- build --reproducible -c test.cage.toml | jq .enclaveMeasurements`

SECOND_PCRS=`cargo run -- build --reproducible -c test.cage.toml | jq .enclaveMeasurements`

echo "Comparing\n$FIRST_PCRS\nWith\n$SECOND_PCRS"
if [ "$FIRST_PCRS" = "$SECOND_PCRS" ]; then
  echo "PCRs match!"
  exit 0
else
  echo "PCRs aren't equal!"
  echo "$FIRST_PCRS" > first-build.json
  echo "$SECOND_PCRS" > second-build.json
  diff first-build.json second-build.json
  exit 1
fi