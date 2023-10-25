#!/usr/bin/env bash

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
