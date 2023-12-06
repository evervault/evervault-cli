#!/bin/sh

pattern="s/1.0.0-dev/$1/"
sed -i -e "$pattern" ./Cargo.toml
