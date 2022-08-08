#!/bin/sh

pattern="s/0.0.0-dev/$1/"
sed -i -e "$pattern" ./Cargo.toml
