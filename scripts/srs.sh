#!/usr/bin/env bash
# Provisions the structured reference strings noir-zk pins in ~/.bb-crs (noir-zk-backend checks their
# SHA-256 and never downloads them), for the proving tests (NOIR_ZK_PROVE). BN254 G1 comes from
# Aztec's CRS host, Grumpkin and the expansion script from zk-encryption v0.1.1 (its recipe).
set -euo pipefail
crs="$HOME/.bb-crs"
points=$(( (1 << 20) + 1 ))
size() { if [ -f "$1" ]; then wc -c < "$1"; else echo 0; fi; }
mkdir -p "$crs"
if [ -f "$crs/grumpkin_g1_v2.flat.dat" ] && [ "$(size "$crs/bn254_g1.dat")" -ge $(( points * 64 )) ]; then
  exit 0
fi
src=$(mktemp -d)
trap 'rm -rf "$src"' EXIT
git clone -q --depth 1 --branch v0.1.1 https://github.com/zk-experiments/zk-encryption "$src"
cp -n "$src/resources/srs/grumpkin_g1_v2.flat.dat" "$crs/" 2>/dev/null || true
if [ "$(size "$crs/bn254_g1.dat")" -lt $(( points * 64 )) ]; then
  curl -fsS -r 0-$(( points * 32 - 1 )) -o "$crs/bn254_g1_compressed.prefix" https://crs.aztec-cdn.foundation/g1_compressed.dat
  python3 "$src/scripts/bn254_srs.py" "$crs/bn254_g1_compressed.prefix" "$crs/bn254_g1.dat" "$points"
  rm -f "$crs/bn254_g1_compressed.prefix"
fi
ls -l "$crs"
