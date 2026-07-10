#!/bin/sh

version="$1"
major="$2"
domain="$3"
darwin_arm64_hash="$4"
darwin_x86_64_hash="$5"
linux_x86_64_hash="$6"
linux_aarch64_hash="$7"

sed \
  -e "s/{{version}}/$version/g" \
  -e "s/{{major}}/$major/g" \
  -e "s/{{domain}}/$domain/g" \
  -e "s/{{darwin_arm64_hash}}/$darwin_arm64_hash/g" \
  -e "s/{{darwin_x86_64_hash}}/$darwin_x86_64_hash/g" \
  -e "s/{{linux_x86_64_hash}}/$linux_x86_64_hash/g" \
  -e "s/{{linux_aarch64_hash}}/$linux_aarch64_hash/g" \
  ./scripts/install.template > ./scripts/install

sed -e "s/{{version}}/$version/g" ./scripts/version.template > ./scripts/version
