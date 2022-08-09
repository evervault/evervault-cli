#!/bin/sh

pattern="s/{{version}}/$1/"

sed -e "$pattern" ./scripts/install.template > ./scripts/install

sed -e "$pattern" ./scripts/version.template > ./scripts/version