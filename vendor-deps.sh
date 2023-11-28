#!/usr/bin/env bash

sed -i "/ssh:\/\/git@github.com\/cipherstash\/cipherstash-suite.git/s/^#//g" Cargo.toml
sed -i "/vendor\/cipherstash-client/s/^/#/g" Cargo.toml

cargo vendor

(
  cd vendor

  # remove deps we don't need
  ls . |\
    grep -xv "cipherstash-client" |\
    grep -xv "cipherstash-core" |\
    grep -xv "vitur-client" |\
    grep -xv "vitur-config" |\
    grep -xv "vitur-protocol" |\
    grep -xv "ore-rs" |\
    grep -xv "recipher" |\
    xargs rm -r
)

sed -i "/ssh:\/\/git@github.com\/cipherstash\/cipherstash-suite.git/s/^/#/g" Cargo.toml
sed -i "/vendor\/cipherstash-client/s/^#//g" Cargo.toml

sed -i "s/\.\.\/\.\.\/packages\/cipherstash-core/..\/cipherstash-core/g" ./vendor/cipherstash-client/Cargo.toml
