#!/bin/sh

pattern="s/{{version}}/$1/"
major_pattern="s/{{major}}/$2/"

sed -e "$pattern" ./scripts/install.template > ./scripts/install
sed -e "$major_pattern" ./scripts/install > ./scripts/install

sed -e "$pattern" ./scripts/version.template > ./scripts/version