#ifndef INT128_H
#define INT128_H
#include "vmlinux.h"

static inline Int128 int128_sub(Int128 a, Int128 b)
{
    return a - b;
}
static inline Int128 int128_make64(uint64_t a)
{
    return a;
}
static inline uint64_t int128_get64(Int128 a)
{
    uint64_t r = a;
 
    return r;
}

static inline Int128 int128_min(Int128 a, Int128 b)
{
    return a < b ? a : b;
}



#endif /* INT128_H */
