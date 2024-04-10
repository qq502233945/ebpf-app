#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include "vmlinux.h"
#include "int128.h"
#define cluster_size 65536
#define l2_slice_size 8192
#define cluster_bits 16
#define l2_bits 13
#define L1E_OFFSET_MASK 0x00fffffffffffe00ULL
#define L2E_SIZE_NORMAL (sizeof(uint64_t))
#define l2_size 8192
#define Qcow2Cache_table_size 65536
#define Qcow2Cache_size 100
#define sc_index 0
#define subcluster_bits 16
#define INV_OFFSET (-1ULL)
typedef enum QCow2SubclusterType {
    QCOW2_SUBCLUSTER_UNALLOCATED_PLAIN,
    QCOW2_SUBCLUSTER_UNALLOCATED_ALLOC,
    QCOW2_SUBCLUSTER_ZERO_PLAIN,
    QCOW2_SUBCLUSTER_ZERO_ALLOC,
    QCOW2_SUBCLUSTER_NORMAL,
    QCOW2_SUBCLUSTER_COMPRESSED,
    QCOW2_SUBCLUSTER_INVALID,
} QCow2SubclusterType;

typedef enum QCow2ClusterType {
    QCOW2_CLUSTER_UNALLOCATED,
    QCOW2_CLUSTER_ZERO_PLAIN,
    QCOW2_CLUSTER_ZERO_ALLOC,
    QCOW2_CLUSTER_NORMAL,
    QCOW2_CLUSTER_COMPRESSED,
} QCow2ClusterType;

typedef enum {
    BDRV_REQ_COPY_ON_READ       = 0x1,
    BDRV_REQ_ZERO_WRITE         = 0x2,

    /*
     * The BDRV_REQ_MAY_UNMAP flag is used in write_zeroes requests to indicate
     * that the block driver should unmap (discard) blocks if it is guaranteed
     * that the result will read back as zeroes. The flag is only passed to the
     * driver if the block device is opened with BDRV_O_UNMAP.
     */
    BDRV_REQ_MAY_UNMAP          = 0x4,

    BDRV_REQ_FUA                = 0x10,
    BDRV_REQ_WRITE_COMPRESSED   = 0x20,

    /*
     * Signifies that this write request will not change the visible disk
     * content.
     */
    BDRV_REQ_WRITE_UNCHANGED    = 0x40,

    /*
     * Forces request serialisation. Use only with write requests.
     */
    BDRV_REQ_SERIALISING        = 0x80,

    /*
     * Execute the request only if the operation can be offloaded or otherwise
     * be executed efficiently, but return an error instead of using a slow
     * fallback.
     */
    BDRV_REQ_NO_FALLBACK        = 0x100,

    /*
     * BDRV_REQ_PREFETCH makes sense only in the context of copy-on-read
     * (i.e., together with the BDRV_REQ_COPY_ON_READ flag or when a COR
     * filter is involved), in which case it signals that the COR operation
     * need not read the data into memory (qiov) but only ensure they are
     * copied to the top layer (i.e., that COR operation is done).
     */
    BDRV_REQ_PREFETCH  = 0x200,

    /*
     * If we need to wait for other requests, just fail immediately. Used
     * only together with BDRV_REQ_SERIALISING. Used only with requests aligned
     * to request_alignment (corresponding assertions are in block/io.c).
     */
    BDRV_REQ_NO_WAIT = 0x400,

    /* Mask of valid flags */
    BDRV_REQ_MASK               = 0x7ff,
} BdrvRequestFlags;

#define MIN(a, b)                                       \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a < _b ? _a : _b;                              \
    })

#define QCOW_OFLAG_COPIED     (1ULL << 63)
#define QCOW_OFLAG_COMPRESSED (1ULL << 62)
#define QCOW_OFLAG_ZERO (1ULL << 0)
#define L2E_OFFSET_MASK 0x00fffffffffffe00ULL
#define BigLittleSwap64(A)        ((((uint64_t)(A) & 0xff00000000000000ull) >> 56) | \
                                    (((uint64_t)(A) & 0x00ff000000000000ull) >> 40) | \
                                    (((uint64_t)(A) & 0x0000ff0000000000ull) >> 24) | \
                                    (((uint64_t)(A) & 0x000000ff00000000ull) >> 8) | \
                                    (((uint64_t)(A) & 0x00000000ff000000ull) << 8) | \
                                    (((uint64_t)(A) & 0x0000000000ff0000ull) << 24) | \
                                    (((uint64_t)(A) & 0x000000000000ff00ull) << 40) | \
                                    (((uint64_t)(A) & 0x00000000000000ffull) << 56))
#define QCOW_OFLAG_SUB_ALLOC(X)   (1ULL << (X))
#define QCOW_OFLAG_SUB_ALLOC_RANGE(X, Y) \
    (QCOW_OFLAG_SUB_ALLOC(Y) - QCOW_OFLAG_SUB_ALLOC(X))
#define QCOW_OFLAG_SUB_ZERO_RANGE(X, Y) \
    (QCOW_OFLAG_SUB_ALLOC_RANGE(X, Y) << 32)
#define swap32Big2Little(x)    ( (x)&(0x00000000ffffffff) ) << 64 |  ( (x)&(0xffffffff00000000) >>64  )



static __inline __bswap_64 (uint64_t __bsx)
{
    return swap32Big2Little (__bsx);
}
static inline int ctz32(uint32_t val)
{
    return val ? __builtin_ctz(val) : 32;
}

static inline int cto32(uint32_t val)
{
    return ctz32(~val);
}

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


inline int64_t offset_into_cluster(int64_t offset)
{
    return offset & (cluster_size - 1);
}

inline int offset_to_l2_slice_index(int64_t offset)
{
    return (offset >> cluster_bits) & (l2_slice_size - 1);
}

inline int64_t offset_to_bytes_available(int64_t offset)
{
    return ((uint64_t)(l2_slice_size - (offset_to_l2_slice_index(offset))))<< cluster_bits;
}

inline int offset_to_l1_index(uint64_t offset)
{
    return offset >> (l2_bits + cluster_bits);
}

static inline int offset_to_l2_index(uint64_t offset)
{
    return (offset >> cluster_bits) & (l2_size - 1);
}

inline uint64_t start_of_slcice(uint64_t offset)
{
    return L2E_SIZE_NORMAL * (offset_to_l2_index(offset)-offset_to_l2_slice_index(offset));
}
inline int offset_to_sc_index(int64_t offset)
{
    return (offset >> 65536) & (1 - 1);
}

inline uint64_t get_l2_entry(uint64_t *l2_slice, int idx)
{
    uint64_t l2_entry;
    idx *= L2E_SIZE_NORMAL / sizeof(uint64_t);
    bpf_copy_from_user(&l2_entry, sizeof(uint64_t), &l2_slice[idx]);
    return BigLittleSwap64(l2_entry);
}
inline uint64_t size_to_clusters(uint64_t size)
{
    return (size + (cluster_size - 1)) >> cluster_bits;
}

static inline QCow2ClusterType qcow2_get_cluster_type(uint64_t l2_entry)
{

    if ((l2_entry & QCOW_OFLAG_ZERO)) {
        if (l2_entry & L2E_OFFSET_MASK) {
            return QCOW2_CLUSTER_ZERO_ALLOC;
        }
        return QCOW2_CLUSTER_ZERO_PLAIN;
    } else if (!(l2_entry & L2E_OFFSET_MASK)) {
        /* Offset 0 generally means unallocated, but it is ambiguous with
         * external data files because 0 is a valid offset there. However, all
         * clusters in external data files always have refcount 1, so we can
         * rely on QCOW_OFLAG_COPIED to disambiguate. */

            return QCOW2_CLUSTER_UNALLOCATED;
    } else {
        return QCOW2_CLUSTER_NORMAL;
    }
}
static inline
QCow2SubclusterType qcow2_get_subcluster_type(uint64_t l2_entry)
{
    
    QCow2ClusterType type = qcow2_get_cluster_type( l2_entry);
     {
        switch (type) {
        case QCOW2_CLUSTER_ZERO_PLAIN:
            return QCOW2_SUBCLUSTER_ZERO_PLAIN;
        case QCOW2_CLUSTER_ZERO_ALLOC:
            return QCOW2_SUBCLUSTER_ZERO_ALLOC;
        case QCOW2_CLUSTER_NORMAL:
            return QCOW2_SUBCLUSTER_NORMAL;
        case QCOW2_CLUSTER_UNALLOCATED:
            return QCOW2_SUBCLUSTER_UNALLOCATED_PLAIN;
        }
    }
}         
static bool cluster_needs_new_alloc(uint64_t l2_entry)
{
    switch (qcow2_get_cluster_type(l2_entry)) {
    case QCOW2_CLUSTER_NORMAL:
    case QCOW2_CLUSTER_ZERO_ALLOC:
        if (l2_entry & QCOW_OFLAG_COPIED) {
            return false;
        }
        /* fallthrough */
    case QCOW2_CLUSTER_UNALLOCATED:
    case QCOW2_CLUSTER_COMPRESSED:
    case QCOW2_CLUSTER_ZERO_PLAIN:
        return true;
    }
}
static int qcow2_get_subcluster_range_type(uint64_t l2_entry,
                                           uint64_t l2_bitmap,
                                           unsigned sc_from,
                                           QCow2SubclusterType *type)
{
    uint32_t val;
    *type = qcow2_get_subcluster_type(l2_entry);
    return 1;

}

static __always_inline int  L2_cache_get_entry(uint32_t index,void *ctxx)
{
	struct L2cache_find_ctx *ctx;
	
	ctx = (struct L2cache_find_ctx *)ctxx;
    Qcow2CachedTable t;
    Qcow2CachedTable *entrites;
    
    // uint64_t pa = ctx->entries_addr+offsetof(struct Qcow2Cache, entries[ctx->i]);
    // entrites = (Qcow2CachedTable *)ctx->entries_addr;
    bpf_copy_from_user(&t, sizeof(Qcow2CachedTable), (Qcow2CachedTable *)(ctx->entries_addr+ctx->i*sizeof(Qcow2CachedTable)));
    // bpf_printk("c addr is %lx,t->offset  is %lx, offset is %lx,ctx->i is %d, t addr is %lx\n",ctx->entries_addr,t.offset,ctx->offset,ctx->i,ctx->entries_addr+ctx->i*sizeof(Qcow2CachedTable));
    if(t.offset == ctx->offset)
    {
        goto found;
    }
    
    if (t.lru_counter < ctx->min_lru_counter) {
        
        ctx->min_lru_counter = t.lru_counter;
        ctx->min_lru_index = ctx->i;
        // bpf_printk("t.lru_counter is %lu, ctx.min_lru_counter is %lu, ctx->min_lru_index is %d \n", t.lru_counter ,ctx->min_lru_counter,ctx->min_lru_index);
    }
    if (++ctx->i == ctx->size) {
        ctx->i = 0;
    }
    if(ctx->i!=ctx->lookup_index)
    {
        return 0;
    }
    else
    {
        return 1;
    }
    found:
        ctx->ret = 1;
        // bpf_uring_write_user(&entrites[ctx->i].ref,&t.ref,sizeof(int)); 
        return 1;
}


static __always_inline uint64_t qcow2_cache_get(uint64_t L2cache_addr, uint64_t l2_offset, int start_of_slice, uint64_t req_offset,uint64_t **l2_slice)
{
    
    int i;
    int ret;
    uint32_t  l2_index;
    uint64_t l2_entry, nb_clusters;
    int lookup_index=0;
    /* Check if the table is already cached */
    uint64_t offset;
    void *table_addr;
    void *buf;
    const int fd = 9;
    struct Qcow2Cache c;
    Qcow2CachedTable t;
    bpf_copy_from_user(&c, sizeof(struct Qcow2Cache), (struct Qcow2Cache *)L2cache_addr);
    offset = l2_offset+start_of_slice;
    

    i = lookup_index = (offset>>14)%c.size;
    struct L2cache_find_ctx ctxx;
    // struct Qcow2Cache t;
    uint64_t file_offset =0;
    file_offset = l2_offset;
    // bpf_printk("l2_index addr is %lx, entry addr is %lx",(uint64_t)L2cache_addr,(uint64_t)&c.entries[0]);
    ctxx.entries_addr = (uint64_t)&c.entries[0];
    ctxx.i = i;
    ctxx.lookup_index = lookup_index;
    ctxx.offset = offset;   
    ctxx.ret = 0;
    ctxx.min_lru_counter = 0xFFFFFFFFFFFFFFF;
    ctxx.size = c.size;
    ctxx.min_lru_index = -1;
    bpf_loop(300, L2_cache_get_entry, &ctxx, 0);
    
    // bpf_printk("i is %d\n",i);
    if(ctxx.ret==1)
    {
       
        goto found;
    }
    else
    {
        // bpf_printk("qcow2_cache_get miss !\n");
        ctxx.i = ctxx.min_lru_index;
        buf = (void *)((uint8_t*)(&c.table_array[0]) + ctxx.i * Qcow2Cache_table_size);
        if(0<c.table_size<0xFFFFF&&file_offset<0xFFFFFFFFFFFF&&file_offset>0)
        {
            c.table_size &= 0xFFFFF;
            file_offset &= 0xFFFFFFFFFFFF;
            bpf_uring_file_read(fd,(void *)buf,c.table_size,(__u64)file_offset);
        }
            
        bpf_uring_write_user((uint64_t)&c.entries[ctxx.i].offset,&l2_offset,sizeof(uint64_t));
        
        

        // c->entries[i].offset = 0;

    }

    found:
        // bpf_printk("L2 Cache hit!,i is %d\n",ctxx.i);
        table_addr = (void *)((uint8_t*)(&c.table_array[0]) + ctxx.i * Qcow2Cache_table_size);
        l2_index = offset_to_l2_slice_index(req_offset);
        l2_entry = get_l2_entry(table_addr,l2_index);
        
        *l2_slice = table_addr;
        // bpf_printk("i is %d, c->table addris is %lx ,table_array addris %lx\n",ctxx.i,(uint64_t)table_addr,(void *)((uint8_t*)(&c.table_array[0])));
        /*update the LRU_counter*/
        /*qcow2_cache_put logical*/

        c.lru_counter++;
        bpf_uring_write_user((uint64_t)&c.entries[ctxx.i].lru_counter,&c.lru_counter,sizeof(uint64_t));
        hwaddr pa = offsetof(struct Qcow2Cache, lru_counter);
         bpf_uring_write_user((uint64_t)L2cache_addr+pa,&c.lru_counter,sizeof(uint64_t));
        
        return l2_entry;
    
}
static int count_sc_subprog(uint32_t index, void *ctxx)
{
    struct count_sc_ctx *ctx = (struct count_sc_ctx*)ctxx;
    QCow2SubclusterType expected_type = QCOW2_SUBCLUSTER_NORMAL, type;
    uint64_t expected_offset = 0;
    bool check_offset = false;
    int ret;
    if(ctx->i < ctx->nb_clusters)
    {
        unsigned first_sc = (ctx->i == 0) ? sc_index : 0;
        uint64_t l2_entry = get_l2_entry( ctx->l2_slice, *ctx->l2_index + ctx->i);
        ret = qcow2_get_subcluster_range_type(l2_entry,0,first_sc,&type);
       
        if (ctx->i == 0) {
            if (type == QCOW2_SUBCLUSTER_COMPRESSED) {
                /* Compressed clusters are always processed one by one */
                ctx->count = ret;
                return 1;
            }
            expected_type = type;
            expected_offset = l2_entry & L2E_OFFSET_MASK;
            check_offset = (type == QCOW2_SUBCLUSTER_NORMAL ||
                            type == QCOW2_SUBCLUSTER_ZERO_ALLOC ||
                            type == QCOW2_SUBCLUSTER_UNALLOCATED_ALLOC);
        } else if (type != expected_type) {
  
             return 1;
        } else if (check_offset) {
            expected_offset += cluster_size;
            if (expected_offset != (l2_entry & L2E_OFFSET_MASK)) {

                 return 1;
            }
        }

        ctx->count += ret;
        /* Stop if there are type changes before the end of the cluster */
        if (first_sc + ret < 1) {
             return 1;
        }
        ctx->i++;
        return 0;
    }
    else
    {
        return 1;
    }

}
static __always_inline int count_contiguous_subclusters(int nb_clusters, uint32_t scindex, uint64_t *l2_slice, unsigned *l2_index)
{
    bool check_offset = false;
    uint64_t l2_bitmap = 0;
    uint64_t expected_offset = 0;
    
    struct count_sc_ctx ctx;
    // if(nb_clusters>10)
    //     return 0;
    ctx.count = 0;
    ctx.l2_slice = l2_slice;
    ctx.l2_index = l2_index;
    ctx.nb_clusters = nb_clusters;
    ctx.i = 0;
    ctx.error = 0;
    bpf_loop(10,count_sc_subprog,&ctx,0);

    return ctx.count;
}
                            
static __always_inline int qcow2_get_host_offset(uint64_t offset,unsigned int *bytes,uint64_t *host_offset,uint64_t L1Cache, uint64_t L2Cache)
{
    uint64_t l2_entry=0;
    uint64_t nb_clusters,*l2_slice;
    uint64_t l2_offset,l1_index;
    uint64_t host_cluster_offset;
    unsigned int offset_in_cluster = offset_into_cluster(offset);
    unsigned int l2_index;
    QCow2SubclusterType type;
    int sc;
	uint64_t bytes_needed = *bytes + offset_in_cluster;
    unsigned int current_byte;
	// bpf_printk("bytes_needed %ld,offset_in_cluster is %d\n",bytes_needed,bytes);
	uint64_t bytes_available = offset_to_bytes_available(offset);
	// bpf_printk("bytes_needed is %ld, bytes_available is %ld\n",bytes_needed,bytes_available);
	if(bytes_needed>bytes_available)
	{
		bytes_needed = bytes_available;
	}
    *host_offset = 0;
	l1_index = offset_to_l1_index(offset);
	
    if(L1Cache!=NULL)
	    bpf_copy_from_user(&l2_offset, sizeof(uint64_t), (uint64_t *)(L1Cache)+l1_index);
	l2_offset = l2_offset & L1E_OFFSET_MASK;
	// bpf_printk("offset is %ld,l1_index is %ld, l2_offset is %ld\n",result->offset,l1_index,l2_offset);
	if(offset_into_cluster(l2_offset))
	{
		bpf_printk("ERROR: offset is not in cluster!\n");
	}

	int start_of_slice = start_of_slcice(offset);
    l2_entry = qcow2_cache_get(L2Cache,l2_offset,start_of_slice,offset,&l2_slice);
    if(l2_entry==0)
    {
        return 0;
    }
    // bpf_printk("table addris %lx, l2_entry  %lx\n",(uint64_t)l2_slice,(uint64_t)l2_entry);
    l2_index = offset_to_l2_slice_index(offset);
    nb_clusters = size_to_clusters(bytes_needed);
    type = qcow2_get_subcluster_type(l2_entry);
     
    switch (type)
    {
    case QCOW2_SUBCLUSTER_INVALID:
        break; /* This is handled by count_contiguous_subclusters() below */
    case QCOW2_SUBCLUSTER_ZERO_PLAIN:
    case QCOW2_SUBCLUSTER_UNALLOCATED_PLAIN:
    break;
    case QCOW2_SUBCLUSTER_NORMAL:
    case QCOW2_SUBCLUSTER_UNALLOCATED_ALLOC: {
        host_cluster_offset = l2_entry & L2E_OFFSET_MASK;
        *host_offset = host_cluster_offset + offset_in_cluster;
        break;
    }
    }
     
    sc = count_contiguous_subclusters(nb_clusters,sc_index,l2_slice,&l2_index);
    // bpf_printk(" sc num  is %u\n",sc);
    // bpf_printk("nb_clusters is %lu, sc is %d,l2_index is %u\n",nb_clusters,sc,l2_index);
    bytes_available = ((int64_t)sc + sc_index) << subcluster_bits;
    // bpf_printk("bytes_available is %lu, bytes_needed is %lu,*bytes is %u\n",bytes_available,bytes_needed,*bytes);
    if (bytes_available > bytes_needed) {
        bytes_available = bytes_needed;
    }
    
    *bytes = bytes_available - offset_in_cluster;
    // bpf_printk("*bytes  is %u\n", *bytes);
    return 1;
    // if(bytes!=0)
    // {
    //     bpf_printk(" Error ! bytes  is %u\n",bytes);
    //     return -1;
    // }
    // else
    //     return 0;
        
}
static __always_inline int  count_single_write_clusters_sub(uint32_t index,void *ctxx)
{
    struct count_s_w_c_ctx *ctx = (struct count_s_w_c_ctx *)ctxx;
    if(ctx->i < ctx->nb_clusters)
    {
        
        ctx->l2_entry = get_l2_entry(ctx->l2_slice,ctx->l2_index+ctx->i);
        if (cluster_needs_new_alloc(ctx->l2_entry) != 0) {
            return 1;
        }
        
        if (ctx->expected_offset != (ctx->l2_entry & L2E_OFFSET_MASK)) {
            return 1;
        }
        ctx->expected_offset += cluster_size;
        
        ctx->i++;
        return 0;
    }
    else
    {
        return 1;
    }
}
static __always_inline int count_single_write_clusters(int nb_clusters,
                                       uint64_t *l2_slice, int l2_index,
                                       bool new_alloc,uint64_t l2_entry)
{
    uint64_t expected_offset = l2_entry & L2E_OFFSET_MASK;

    // bpf_printk("l2_slice %lx, l2_slice %u, expected_offset is %lx,nb_clusters is %d\n",l2_slice,l2_index,expected_offset,nb_clusters);
    struct count_s_w_c_ctx ctx;
    ctx.expected_offset = expected_offset;
    ctx.i = 0;
    ctx.l2_entry = l2_entry;
    ctx.l2_index = l2_index;
    ctx.l2_slice = l2_slice;
    ctx.nb_clusters = nb_clusters;
    bpf_loop(10, count_single_write_clusters_sub, &ctx, 0);
    return ctx.i;
}
static __always_inline uint64_t get_cluster_table(uint64_t offset, uint64_t **new_l2_slice, int *new_l2_index,uint64_t L1Cache, uint64_t L2Cache,int *ret)
{
    unsigned int l2_index;
    uint64_t l1_index, l2_offset=0;
    uint64_t *l2_slice = NULL;
    int start_of_slice;
    uint64_t l2_entry=0;
    l1_index = offset_to_l1_index(offset);
    if(L1Cache!=NULL)
	    bpf_copy_from_user(&l2_offset, sizeof(uint64_t), (uint64_t *)(L1Cache)+l1_index);
    if(!(l2_offset&QCOW_OFLAG_COPIED))
    {
         /* First allocate a new L2 table (and do COW if needed) */
         *ret = 111;

    }
    l2_offset = l2_offset& L1E_OFFSET_MASK;

    


    start_of_slice= start_of_slcice(offset);

    // bpf_printk("start_of_slice is %d",start_of_slice);
    l2_entry = qcow2_cache_get(L2Cache,l2_offset,start_of_slice,offset,&l2_slice);
    l2_index = offset_to_l2_slice_index(offset);
    *new_l2_slice = l2_slice;
    *new_l2_index = l2_index;
    
    return l2_entry;

}


static __always_inline int handle_copied(uint64_t guest_offset, uint64_t *host_offset, uint64_t *bytes,uint64_t L1Cache, uint64_t L2Cache)
{
    int l2_index;
    uint64_t *l2_slice;
    uint64_t nb_clusters;
    uint64_t l2_entry,cluster_offset;
    int ret = -1;
    uint64_t alloc_cluster_offset;
    unsigned int keep_clusters;
    nb_clusters = size_to_clusters(offset_into_cluster(guest_offset) + *bytes);
    // bpf_printk("nb_clusters  1 is %ld, offset_into_cluster is %ld, bytes is %lu \n",nb_clusters,offset_into_cluster(guest_offset),*bytes);
    l2_index = offset_to_l2_slice_index(guest_offset);
    nb_clusters = MIN(nb_clusters, l2_slice_size - l2_index);
    //bpf_printk("nb_clusters  2 is %ld\n",nb_clusters);
    l2_entry = get_cluster_table(guest_offset, &l2_slice, &l2_index,L1Cache,L2Cache,&ret);
    if(ret=111)
    {
        ret = 0;
        goto out;
    }
    cluster_offset = l2_entry & L2E_OFFSET_MASK;
    // bpf_printk("cluster_offset is %lx\n",cluster_offset);
    if(!cluster_needs_new_alloc(l2_entry))
    {
        if (*host_offset != INV_OFFSET && cluster_offset != *host_offset) {
            *bytes = 0;
            ret = 0;
            bpf_printk("cluster_needs_new_alloc\n");
            goto out;
        }

        keep_clusters = count_single_write_clusters(nb_clusters, l2_slice, l2_index, false, l2_entry);

        *bytes = MIN(*bytes, keep_clusters * cluster_size- offset_into_cluster(guest_offset));
        // bpf_printk("handle_copied is bytes %lu\n",*bytes );
        ret = 1;
    }
    else
    {
        ret = 0;
        goto out;
    }
    out:
        if (ret > 0) {
        *host_offset = cluster_offset + offset_into_cluster(guest_offset);
        }
        return ret;
}

static __always_inline int qcow2_alloc_host_offset(uint64_t offset, unsigned int *bytes, uint64_t *host_offset,uint64_t L1Cache, uint64_t L2Cache)                                         
{
    uint64_t cluster_offset;
    uint64_t cur_bytes;
    uint64_t start, remaining;
    int ret;
    remaining = *bytes;

    cluster_offset = INV_OFFSET;
    cur_bytes = 0;
    cur_bytes = remaining;

    ret = handle_copied(offset,&cluster_offset,&cur_bytes,L1Cache,L2Cache);
    if(ret)
    {
        *bytes = cur_bytes;
        *host_offset = cluster_offset;
        // bpf_printk("cluster_offset is bytes %lx\n",cluster_offset);
        return 0;
    }
    else
    {
        return -1;
    }

    // bpf_printk("cluster_offset is bytes %lx\n",cluster_offset);
    return 0;
}


static __always_inline long pwritev_loop(uint32_t index,void *ctxx)
{
    int offset_in_cluster;
    int ret;
    struct qcow2_co_pwritev_ctx *ctx = (struct qcow2_co_pwritev_ctx*)ctxx;
        
    offset_in_cluster = offset_into_cluster(ctx->offset);
    ctx->curent_bytes = MIN(ctx->bytes,0xFFFFFF);
    ret = qcow2_alloc_host_offset(ctx->offset, &ctx->curent_bytes, &ctx->host_offset,ctx->L1Cache,ctx->L2Cache);
    if(ret<0)
    {
        ctx->need_alloc = 1;
        return 1;
    }
    // bpf_printk("pwritev_part index is %u,offset is %ld, curent_bytes %u,  ctx->bytes is %ld\n",index,ctx->offset,ctx->curent_bytes,ctx->bytes);
    // if(index>0)
    // {
    //     bpf_printk("qcow2_co_pwritev_ppwritev_loop \n");
    //     bpf_printk("qcow2_co_pwritev_part multi,host_offset is %lx,i is %ld, ctx->offset %u,  ctx->bytes is %ld\n",ctx->host_offset,ctx->offset,ctx->curent_bytes,ctx->bytes);
    // }
    // bpf_printk("qcow2_co_pwritev_part, host_offset is %lx,offset is %ld, cur_bytes is %u,  qiov_offset is %lx\n",ctx->host_offset,ctx->offset,ctx->curent_bytes,ctx->qiov_offset);

    ctx->qiov->offset = ctx->host_offset;
    bpf_map_update_elem(ctx->map, &ctx->qiov->id, ctx->qiov, BPF_ANY);   

    if(ctx->bytes == ctx->curent_bytes)
    {
        // bpf_printk("NOTIFY host_offset is %lx,offset is %ld, cur_bytes is %u,  qiov_offset is %lx\n",\
        ctx->host_offset,ctx->offset,ctx->curent_bytes,ctx->qiov_offset);

        bpf_map_update_elem(ctx->user_map, &ctx->qiov->id, ctx->user, BPF_ANY);
       	if(ctx->qiov->id < 10000)
		    ret = bpf_io_uring_submit(ctx->ctxx,ctx->qiov->id,ctx->qiov_offset,ctx->curent_bytes,NOTIFY);
    } 
    else
    {
        // bpf_printk("Slience host_offset is %lx,offset is %ld, cur_bytes is %u,  qiov_offset is %lx\n",\
        ctx->host_offset,ctx->offset,ctx->curent_bytes,ctx->qiov_offset);
        
        if(ctx->qiov->id < 10000)
		    ret = bpf_io_uring_submit(ctx->ctxx,ctx->qiov->id,ctx->qiov_offset,ctx->curent_bytes,0);
    }


    ctx->bytes -= ctx->curent_bytes;
    ctx->offset += ctx->curent_bytes;
    ctx->qiov_offset += ctx->curent_bytes;
    ctx->iter++;

    if(ctx->bytes == 0)
    {
        return 1;
    }
    return 0;
}

static __always_inline  int qcow2_co_pwritev_part(int64_t offset, int64_t bytes,
        Fast_map *qiov, struct io_uring_bpf_ctx *ctxx,uint64_t L1Cache, uint64_t L2Cache,void* map,void* user_map,struct Useraddr *user)
{
    int offset_in_cluster;
    int ret;
    uint64_t host_offset;
    unsigned int cur_bytes; 

    struct qcow2_co_pwritev_ctx ctx;
    ctx.offset = offset;
    ctx.bytes = bytes;
    ctx.curent_bytes = 0;
    ctx.host_offset = 0;
    ctx.qiov = qiov;
    ctx.qiov_offset = 0;
    ctx.iter = 0;
    ctx.L1Cache = L1Cache;
    ctx.L2Cache = L2Cache;
    ctx.ctxx = ctxx;
    ctx.map = map;
    ctx.user_map = user_map;
    ctx.user = user;
    ctx.need_alloc = 0;
    bpf_loop(30, pwritev_loop, &ctx, 0);
    if(ctx.need_alloc==1)
        return -1;
    return ctx.iter;
}

static __always_inline long preadv_loop(uint32_t index,void *ctxx)
{
    int offset_in_cluster;
    int ret;
    struct qcow2_co_preadv_ctx *ctx = (struct qcow2_co_preadv_ctx*)ctxx;
        

    ctx->curent_bytes = MIN(ctx->bytes,0xFFFFFFFF);
    ret = qcow2_get_host_offset(ctx->offset, &ctx->curent_bytes, &ctx->host_offset,ctx->L1Cache,ctx->L2Cache);
        // bpf_printk("qcow2_co_readv_part multi,host_offset is %lx,i is %ld, ctx->offset %u,  ctx->bytes is %ld\n",ctx->host_offset,ctx->offset,ctx->curent_bytes,ctx->bytes);
    // bpf_printk("current_byte is %u, bytes is %ld\n",ctx->curent_bytes,ctx->bytes);
    // if(index>0)
    // {
    //     bpf_printk("qcow2_co_readv_part \n");
    //     bpf_printk("qcow2_co_pwritev_part multi,host_offset is %lx,i is %ld, ctx->offset %u,  ctx->bytes is %ld\n",ctx->host_offset,ctx->offset,ctx->curent_bytes,ctx->bytes);
    // }
    // if( ctx->bytes!=ctx->curent_bytes)
    // {
    //     bpf_printk("Error! mutiloop preadv\n");
    //     bpf_printk("current_byte is %u, bytes is %ld\n",ctx->curent_bytes,ctx->bytes);
    // }

    // bpf_printk("qcow2_co_preadv_part, host_offset is %lx,offset is %ld, cur_bytes is %u,  qiov_offset is %lx\n",ctx->host_offset,ctx->offset,ctx->curent_bytes,ctx->qiov_offset);

    ctx->qiov->offset = ctx->host_offset;
    bpf_map_update_elem(ctx->map, &ctx->qiov->id, ctx->qiov, BPF_ANY);   

    if(ctx->bytes == ctx->curent_bytes)
    {
        //  bpf_printk("NOTIFY host_offset is %lx,offset is %ld, cur_bytes is %u,  qiov_offset is %lx\n",\
        // ctx->host_offset,ctx->offset,ctx->curent_bytes,ctx->qiov_offset);       
        bpf_map_update_elem(ctx->user_map, &ctx->qiov->id, ctx->user, BPF_ANY);
       	if(ctx->qiov->id < 10000)
		    ret = bpf_io_uring_submit(ctx->ctxx,ctx->qiov->id,ctx->qiov_offset,ctx->curent_bytes,NOTIFY);
    } 
    else
    {
        // bpf_printk("Slience host_offset is %lx,offset is %ld, cur_bytes is %u,  qiov_offset is %lx\n",\
        // ctx->host_offset,ctx->offset,ctx->curent_bytes,ctx->qiov_offset);
        if(ctx->qiov->id < 10000)
		    ret = bpf_io_uring_submit(ctx->ctxx,ctx->qiov->id,ctx->qiov_offset,ctx->curent_bytes,0);
    }

	// 	bpf_printk("bpf_io_uring_submit ret is %d\n",ret);
    ctx->bytes -= ctx->curent_bytes;
    ctx->offset += ctx->curent_bytes;
    ctx->qiov_offset += ctx->curent_bytes;
    ctx->iter++;

    if(ctx->bytes == 0)
    {
        return 1;
    }
    return 0;
}


static __always_inline  int qcow2_co_preadv_part(int64_t offset, int64_t bytes,
        Fast_map *qiov, struct io_uring_bpf_ctx *ctxx,uint64_t L1Cache, uint64_t L2Cache,void* map,void* user_map,struct Useraddr *user)
{
    int offset_in_cluster;
    int ret;
    uint64_t host_offset;
    unsigned int cur_bytes; 

    struct qcow2_co_preadv_ctx ctx;
    ctx.offset = offset;
    ctx.bytes = bytes;
    ctx.curent_bytes = 0;
    ctx.host_offset = 0;
    ctx.qiov = qiov;
    ctx.qiov_offset = 0;
    ctx.iter = 0;
    ctx.L1Cache = L1Cache;
    ctx.L2Cache = L2Cache;
    ctx.ctxx = ctxx;
    ctx.map = map;
    ctx.user_map = user_map;
    ctx.user = user;
    bpf_loop(30, preadv_loop, &ctx, 0);
    return ctx.iter;
}
