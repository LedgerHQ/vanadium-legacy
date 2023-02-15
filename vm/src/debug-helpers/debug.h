#pragma once

#include "os.h"

void debug_write(const char *buf);

int semihosted_printf(const char *format, ...);
