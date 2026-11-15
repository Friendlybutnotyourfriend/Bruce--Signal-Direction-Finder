#pragma once
#include <stddef.h>
constexpr unsigned MALLOC_CAP_DMA = 1;
size_t heap_caps_get_largest_free_block(unsigned caps);
