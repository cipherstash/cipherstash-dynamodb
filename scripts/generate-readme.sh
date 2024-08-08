#!/bin/bash

# This script generates a README.md file from the lib.rs which is the source of truth for the README.md file.
# It will replace all the contents between:
#
# <!-- cargo-rdme start -->
# ...
# <!-- cargo-rdme end -->
#
# with the contents of the comments in the lib.rs file.

cargo rdme --heading-base-level 0