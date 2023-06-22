#include "vmlinux.h"

inline int64_t int128_gethi(Int128 a)
{
    return a >> 64;
}
inline uint64_t int128_getlo(Int128 a)
{
    return a;
}

inline uint64_t range_get_last(uint64_t offset, uint64_t len)
{
    return offset + len - 1;
}

inline int range_covers_byte(uint64_t offset, uint64_t len,
                                    uint64_t byte)
{
    return offset <= byte && byte <= range_get_last(offset, len);
}

inline bool section_covers_addr(const MemoryRegionSection *section,
                                       hwaddr addr)
{
    /* Memory topology clips a memory region to [0, 2^64); size.hi > 0 means
     * the section must cover the entire address space.
     */
    return int128_gethi(section->size) ||
           range_covers_byte(section->offset_within_address_space,
                             int128_getlo(section->size), addr);
}