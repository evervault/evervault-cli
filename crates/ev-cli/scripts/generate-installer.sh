#!/bin/sh

pattern="s/{{version}}/$1/"
major_pattern="s/{{major}}/$2/"
domain_pattern="s/{{domain}}/$3/"
macos_hash_pattern="s/{{macos_hash}}/$4/"
linux_hash_pattern="s/{{linux_hash}}/$5/"

sed -e "$pattern" ./scripts/install.template > ./scripts/install-temp
sed -e "$domain_pattern" ./scripts/install-temp > ./scripts/install-temp-domain
sed -e "$major_pattern" ./scripts/install-temp-domain > ./scripts/install-temp-major
sed -e "$macos_hash_pattern" ./scripts/install-temp-major > ./scripts/install-temp-macos
sed -e "$linux_hash_pattern" ./scripts/install-temp-macos > ./scripts/install

sed -e "$pattern" ./scripts/version.template > ./scripts/version

rm ./scripts/install-temp ./scripts/install-temp-domain ./scripts/install-temp-major ./scripts/install-temp-macos
