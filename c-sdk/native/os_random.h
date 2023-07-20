#pragma once

#include <stdint.h>

typedef uint32_t cx_err_t;

cx_err_t cx_get_random_bytes(void *buffer, size_t len);
