#!/bin/bash

# Apply clang-format on the whole C code base.
#
# A custom clang-format binary can be specified thanks to the CLANG_FORMAT
# environment variable.

set -e

CLANG_FORMAT="${CLANG_FORMAT:-clang-format}"

# use xargs to quit if clang-format terminates with a non-zero exit status
find c-sdk/ \
     -name '*.[ch]' \
     -exec "${CLANG_FORMAT}" -style=file -Werror --dry-run '{}' '+'
