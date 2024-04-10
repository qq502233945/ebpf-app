#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include "help.c"
#include "vmlinux.h"
#include "int128.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16*4096*2048);
} kernel_ringbuf SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct VirtQueue);
	__uint(max_entries, 8);
} vq_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct VRingDesc);
	__uint(max_entries, 256*8);
} descs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct VRingDesc);
	__uint(max_entries, 8);
} descs_cache SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, VRMRCS);
	__uint(max_entries, 8);
} VRMRC SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct MemoryRegionCache);
	__uint(max_entries, 8);
} MRC SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct VirtIODevice);
	__uint(max_entries, 8);
} VDEV SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct AddressSpace);
	__uint(max_entries, 8);
} AS SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct MemoryRegionCache);
	__uint(max_entries, 8);
} IDC SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct flatview);
	__uint(max_entries, 8);
} Cache_FLATV SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct AddressSpaceDispatch);
	__uint(max_entries, 8);
} Dispatch SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct MemoryRegionSection);
	__uint(max_entries, 8);
} Dispatch_MRU SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, Node);
	__uint(max_entries, 8);
} Dispatch_M_Node SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct MemoryRegionSection);
	__uint(max_entries, 3*8);
} Dispatch_M_Sec SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct MemoryRegionSection);
	__uint(max_entries, 8);
} MRS SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, MemoryRegion);
	__uint(max_entries, 8);
} MR SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, MemoryRegion);
	__uint(max_entries, 8);
} Section_MR SEC(".maps");
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, subpage_t);
	__uint(max_entries, 8);
} Subpage SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, RAMBlock);
	__uint(max_entries, 8);
} RB SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, Fast_map);
	__uint(max_entries, 8);
} fast_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, Fast_map);
	__uint(max_entries, 8*256+1);
} fast_map_d SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 8);
} Router SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 8);
} QemuRouter SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, Useraddr);
	__uint(max_entries, 2048+1);
} User_addr_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, Useraddr);
	__uint(max_entries, 8);
} avail_addr_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct virtio_blk_outhdr);
	__uint(max_entries, 8);
} outhdr SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, uint16_t);
	__uint(max_entries, 8);
} old_avail_idx SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct req_pop_ctx);
	__uint(max_entries, 8);
} req_pop SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 8);
} vq_inuse SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, uint32_t);
	__uint(max_entries, 1);
} exit_count SEC(".maps");
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct io_uring_sqe_bpf);
	__uint(max_entries, 256 * 8);
} Sqes SEC(".maps");

static inline void barrier_bpf()
{
	asm volatile("" : : : "memory");
}

static inline void ramblock_ptr(RAMBlock *block, ram_addr_t offset, ram_addr_t *ptr, uint32_t vq_id)
{
	RAMBlock *rb;
	rb = bpf_map_lookup_elem(&RB, &vq_id);
	if (rb)
	{	
		bpf_copy_from_user(rb, sizeof(RAMBlock), block);
		if (rb->host && offset < rb->used_length)
		{
			*ptr = rb->host + offset;
		}
		else
		{
			*ptr = NULL;
		}
	}
}

static inline void ramblock_ptr_d(RAMBlock *block, ram_addr_t offset, ram_addr_t *ptr, uint32_t vq_id)
{
	RAMBlock *rb;
	rb = bpf_map_lookup_elem(&RB, &vq_id);
	if (rb)
	{	
		
		bpf_copy_from_user(rb, sizeof(RAMBlock), block);
		// bpf_printk(" rb->host addr is %x, rb->used_length is %lu\n",rb->host,rb->used_length);
		if (rb->host && offset < rb->used_length)
		{
			*ptr = rb->host + offset;
		}
		else
		{
			*ptr = NULL;
		}
	}
}

static __always_inline bool memory_region_is_ram(MemoryRegion *mr,uint32_t vq_id)
{
	MemoryRegion *mrr;
	mrr = bpf_map_lookup_elem(&MR, &vq_id);
	if (mrr)
	{
		bpf_copy_from_user(mrr, sizeof(MemoryRegion), mr);
		return mrr->ram;
	}
	return 0;
}
static inline bool memory_access_is_direct(MemoryRegion *mr, bool is_write,uint32_t vq_id)
{
	MemoryRegion *mrr;
	mrr = bpf_map_lookup_elem(&MR, &vq_id);
	if (mrr)
	{
		bpf_copy_from_user(mrr, sizeof(MemoryRegion), mr);
		if (is_write)
		{
			return mrr->ram && !mrr->readonly &&
				   !mrr->rom_device && !mrr->ram_device;
		}
		else
		{
			return (mrr->ram && !mrr->ram_device) ||
				   mrr->rom_device;
		}
	}
	return 0;
}


static int  phys_page_find_sub(uint32_t index, void *ctxx)
{
	struct phys_page_find_ctx *ctx;
	
	ctx = (struct phys_page_find_ctx *)ctxx;
	if(ctx->lp->skip&&((*ctx->i-=ctx->lp->skip)>=0))
	{	

		if(ctx->lp->ptr == PHYS_MAP_NODE_NIL)
		{
			bpf_copy_from_user(ctx->section, sizeof(struct MemoryRegionSection), &ctx->d->map.sections[0]);
			*ctx->ret = 1;
			return 1;
		}
		bpf_copy_from_user(ctx->nodes, sizeof(Node), &ctx->d->map.nodes[ctx->lp->ptr]);
		ctx->p = ctx->nodes;
		ctx->lp = &ctx->p[(*ctx->indexx >> (*ctx->i * P_L2_BITS)) & (P_L2_SIZE - 1)];
	}
	return 0;
}




static __always_inline uint32_t  phys_page_find(AddressSpaceDispatch *d, hwaddr addr, uint32_t vq_id)
{
	PhysPageEntry lp = d->phys_map, *p;
	uint32_t arrary_num = 0;
	Node *nodes;
	struct MemoryRegionSection *section, *section1;
	hwaddr addrr;
	uint32_t num;
	struct phys_page_find_ctx ctx;
	#pragma unrol
	nodes = bpf_map_lookup_elem(&Dispatch_M_Node, &vq_id);
	num = arrary_num + 3 *vq_id;
	section = bpf_map_lookup_elem(&Dispatch_M_Sec, &num);
	int i, t;
	bool ret=0;
	
	if (nodes && section)
	{

		bpf_copy_from_user(nodes, sizeof(Node), d->map.nodes);
		addrr = addr >> TARGET_PAGE_BITS;
		t =20;
		i = P_L2_LEVELS;
		ctx.d = d;
		ctx.lp = &lp;
		ctx.nodes = nodes;
		ctx.p = p;
		ctx.i = &i;
		ctx.section = section;
		ctx.ret = &ret;
		ctx.indexx = &addrr;
		bpf_loop(t, phys_page_find_sub, &ctx, 0);
		if(*ctx.ret)
			return 0;
		// for (i = P_L2_LEVELS; lp.skip && (i -= lp.skip) >= 0; )
		// {
		// 	if (lp.ptr == PHYS_MAP_NODE_NIL)
		// 	{

		// 		bpf_copy_from_user(section, sizeof(struct MemoryRegionSection), &d->map.sections[0]);
		// 		return 0;
		// 	}
		// 	bpf_copy_from_user(nodes, sizeof(Node), d->map.nodes[lp.ptr]);
		// 	p = nodes;
		// 	lp = p[(index >> (i * P_L2_BITS)) & (P_L2_SIZE - 1)];
		// 	t--;
		// }
		
		arrary_num = 1;
		num = arrary_num + 3 *vq_id;
		section1 = bpf_map_lookup_elem(&Dispatch_M_Sec, &num);
		
		if (section1)
		{
			
			bpf_copy_from_user(section1, sizeof(struct MemoryRegionSection), &d->map.sections[ctx.lp->ptr]);
			if (section_covers_addr(section1, addr))
			{
				return 1;
			}
			else
			{
				bpf_copy_from_user(section, sizeof(struct MemoryRegionSection), &d->map.sections[0]);
				return 0;
			}
		}
	}
	
	return 0;
}


static __always_inline uint32_t address_space_lookup_region(AddressSpaceDispatch *d, struct MemoryRegionSection *section, hwaddr addr, bool resolve_subpage,uint32_t vq_id)
{
	uint32_t arrary_num = 0;
	uint32_t ret = 0;
	uint32_t num;
	struct MemoryRegionSection *section1;
	struct MemoryRegion *mr;
	subpage_t *subpage;
	uint64_t sub=0;
	num = ret+vq_id*3;
	bpf_map_update_elem(&Dispatch_M_Sec, &num, section, BPF_ANY);
	
	if (!section_covers_addr(section, addr) || !section || d->mru_section == &d->map.sections[0])
	{

		// bpf_printk("step 2\n");
		
		ret = phys_page_find(d, addr,vq_id);
		
		num = ret+vq_id*3;
		section1 = bpf_map_lookup_elem(&Dispatch_M_Sec, &num);
		if (section1)
		{
			bpf_map_update_elem(&Dispatch_MRU, &vq_id, section1, BPF_ANY);
		}

	}
	
	section1 = bpf_map_lookup_elem(&Dispatch_MRU, &vq_id);
	mr = bpf_map_lookup_elem(&Section_MR, &vq_id);
	if(mr&&section1)
	{
		bpf_copy_from_user(mr, sizeof(struct MemoryRegion), section1->mr);
		if(resolve_subpage&&mr->subpage)
		{
			subpage = container_of(section->mr, subpage_t, iomem);
			
			hwaddr pa = offsetof(subpage_t, sub_section[SUBPAGE_IDX(addr)]);
			bpf_copy_from_user(&sub, sizeof(uint16_t), (void *)(subpage+ pa));
			hwaddr pa2 = offsetof(PhysPageMap, sections[sub]);
			bpf_copy_from_user(section1, sizeof(struct MemoryRegionSection), (void *)(&d->map+ pa2));
			arrary_num = 2;
			num = arrary_num+vq_id*3;
			bpf_map_update_elem(&Dispatch_M_Sec, &num, section1, BPF_ANY);
			ret = 2;
			bpf_printk("ret is %u\n",ret);
		}
	}
	
	return ret;
}


static __always_inline int address_space_translate_internal(AddressSpaceDispatch *d, hwaddr addr, hwaddr *xlat,
															hwaddr *plen, bool resolve_subpage, bool init,uint32_t vq_id)
{
	uint32_t arrary_num = 0, ret;
	struct MemoryRegionSection *section;
	Int128 diff;
	uint32_t num;
	section = bpf_map_lookup_elem(&Dispatch_MRU, &vq_id);
	if (section)
	{

		bpf_copy_from_user(section, sizeof(struct MemoryRegionSection), d->mru_section);
		ret = address_space_lookup_region(d, section, addr, resolve_subpage,vq_id);
		num = ret+vq_id*3;
		section = bpf_map_lookup_elem(&Dispatch_M_Sec, &num);

		if (section)
		{
			addr -= section->offset_within_address_space;
			*xlat = addr + section->offset_within_region;
			
			if(init)
			{
				diff = int128_sub(section->size, int128_make64(addr));
				*plen = int128_get64(int128_min(diff, int128_make64(*plen)));

				return ret;
			}
			if (memory_region_is_ram(section->mr,vq_id))
			{
				diff = int128_sub(section->size, int128_make64(addr));
				*plen = int128_get64(int128_min(diff, int128_make64(*plen)));
			}
			return ret;
		}
	}

	return 0;
}


static __always_inline uint32_t address_space_cache_init(AddressSpace *as,
														 hwaddr addr,
														 hwaddr len,
														 bool is_write,
														 uint32_t vq_id)
{
	struct MemoryRegionCache *i_desc_cache;
	struct flatview *view;
	struct AddressSpaceDispatch *d;
	struct MemoryRegionSection *section;
	MemoryRegion *mrr;
	uint32_t arrary_num = 0, ret = 0;
	hwaddr l;
	Int128 diff;
	uint32_t num;
	l = len;
	i_desc_cache = bpf_map_lookup_elem(&IDC, &vq_id);
	view = bpf_map_lookup_elem(&Cache_FLATV, &vq_id);
	d = bpf_map_lookup_elem(&Dispatch, &vq_id);
	if (i_desc_cache && d && view)
	{
		bpf_copy_from_user(view, sizeof(struct flatview), as->current_map);
		bpf_copy_from_user(d, sizeof(struct AddressSpaceDispatch), view->dispatch);
		
		ret = address_space_translate_internal(d, addr, &i_desc_cache->xlat, &l, true,1,vq_id);


		arrary_num = ret;
		num = arrary_num+3*vq_id;
		section = bpf_map_lookup_elem(&Dispatch_M_Sec, &num);
		if (section)
		{
			
			diff = int128_sub(section->size, int128_make64(i_desc_cache->xlat - section->offset_within_region));
			l = int128_get64(int128_min(diff, int128_make64(l)));
			
			if (memory_access_is_direct(section->mr, is_write,vq_id))
			{
				mrr = bpf_map_lookup_elem(&MR, &vq_id);
				if (mrr)
				{
					// bpf_printk(" section mr addr arrary_num  is %u\n",section->mr);
					ramblock_ptr_d(mrr->ram_block, i_desc_cache->xlat, &i_desc_cache->ptr,vq_id);
				}
			}
			else
			{
				// mrr = bpf_map_lookup_elem(&MR, &vq_id);
				// if (mrr)
				// {
				// 	bpf_printk(" error section mr addr arrary_num  is %u\n",section->mr);
				// }

				i_desc_cache->ptr = NULL;
			}
			i_desc_cache->len = l;
			i_desc_cache->is_write = is_write;
			return l;
		}
	}
	return 0;
}


static __always_inline uint32_t vring_split_desc_read(struct MemoryRegionCache *desc_cache, uint32_t head_num, uint32_t *ret, uint32_t vq_id,uint32_t desc_id) // To get the head vring
{
	struct VRingDesc *vrdesc;
	uint32_t num;
	num = desc_id+vq_id*256;
	vrdesc = bpf_map_lookup_elem(&descs, &num);
	if (vrdesc)
	{
		bpf_copy_from_user(vrdesc, sizeof(struct VRingDesc), desc_cache->ptr + head_num * sizeof(struct VRingDesc));
	}

	return 0;
}
static __always_inline uint32_t vring_split_desc_read_d(struct MemoryRegionCache *desc_cache, uint32_t head_num, uint32_t *ret, uint32_t vq_id,uint32_t desc_id) // To get the head vring
{
	struct VRingDesc *vrdesc;

	uint32_t num;
	num = desc_id+vq_id*256;
	vrdesc = bpf_map_lookup_elem(&descs, &num);
	if (vrdesc)
	{
		bpf_copy_from_user(vrdesc, sizeof(struct VRingDesc), desc_cache->ptr + head_num * sizeof(struct VRingDesc));
		if(vrdesc->len != 16)
		{
			bpf_printk("*************\n");
			bpf_printk("vq_id is %lu\n",vq_id);
			bpf_printk("desc_cache xlat is %lu\n",desc_cache->xlat);
			bpf_printk("desc_cache ptr is 0x%lx\n",desc_cache->ptr);
			bpf_printk("desc->addr is %lu, desc->len is %u\n",vrdesc->addr, vrdesc->len);
			return -1; 
		}	
		// bpf_printk("vq_id is %lu\n",vq_id);
		// bpf_printk("desc_cache xlat is %lu\n",desc_cache->xlat);
		// bpf_printk("desc_cache ptr is 0x%lx\n",desc_cache->ptr);
		// bpf_printk("desc->addr is %lu, desc->len is %u\n",vrdesc->addr, vrdesc->len);
	}

	return 0;
}
static __always_inline uint32_t vring_split_desc_read_cache(struct MemoryRegionCache *desc_cache, uint32_t head_num, uint32_t *ret, uint32_t vq_id) // To get the head vring
{
	struct VRingDesc *vrdesc;
	vrdesc = bpf_map_lookup_elem(&descs_cache, &vq_id);
	if (vrdesc)
	{
		bpf_copy_from_user(vrdesc, sizeof(struct VRingDesc), desc_cache->ptr + head_num * sizeof(struct VRingDesc));
		if (ret != NULL)
		{
			*ret = vrdesc->next;
		}
	}
	return 0;
}
static uint16_t vring_get_region_caches(struct VirtQueue *vq) //
{
	int ret = 0;
	VRMRCS *caches;
	caches = bpf_map_lookup_elem(&VRMRC, &vq->queue_index);
	if (caches)
	{
		bpf_copy_from_user(caches, sizeof(VRMRCS), vq->vring.caches);
	}
	

	return 0;
}

static inline int flatview_do_translate(flatview *fv,
										hwaddr addr,
										hwaddr *xlat,
										hwaddr *plen_out,
										hwaddr *page_mask_out,
										bool is_write,
										bool is_mmio,
										MemTxAttrs attrs,
										uint32_t vq_id)
{
	MemoryRegionSection *section;
	uint32_t arrary_num = 0;
	int ret = 0;
	hwaddr plen = (hwaddr)(-1);
	AddressSpaceDispatch *d;
	if (!plen_out)
	{
		plen_out = &plen;
	}
	d = bpf_map_lookup_elem(&Dispatch, &vq_id);
	if (d)
	{
		bpf_copy_from_user(d, sizeof(AddressSpaceDispatch), fv->dispatch);

		ret = address_space_translate_internal(d, addr, xlat, plen_out, is_mmio,0,vq_id);

		return ret;
	}
	return 0;
}

static inline int flatview_translate(flatview *fv, hwaddr addr, hwaddr *xlat,
									 hwaddr *plen, bool is_write,
									 MemTxAttrs attrs, uint32_t vq_id)
{
	int ret = 0;
	ret = flatview_do_translate(fv, addr, xlat, plen, NULL,
								is_write, true, attrs,vq_id);

	return ret;
}

static inline ram_addr_t *dma_memory_map(AddressSpace *dma_as, dma_addr_t addr, dma_addr_t *len,
										 DMADirection dir, MemTxAttrs attrs, ram_addr_t *iov_base,uint32_t vq_id)
{
	hwaddr xlen = *len;
	uint32_t arrary_num = 0;
	hwaddr l, xlat, temp;
	flatview *fv;
	MemoryRegionSection *section;
	MemoryRegion *mrr;
	void *temp_ptr = NULL;
	uint32_t num;
	int ret = 0;
	xlat = 0;
	l = xlen;
	fv = bpf_map_lookup_elem(&Cache_FLATV, &vq_id);
	if (fv)
	{
		bpf_copy_from_user(fv, sizeof(struct flatview), dma_as->current_map);
		ret = flatview_translate(fv, addr, &xlat, &l, dir == DMA_DIRECTION_FROM_DEVICE, attrs,vq_id);
		if (ret == 1)
		{
			arrary_num = 1;
		}
		num = arrary_num+3*vq_id;
		section = bpf_map_lookup_elem(&Dispatch_M_Sec, &num);
		if (section)
		{
			mrr = bpf_map_lookup_elem(&MR, &vq_id);
			if (mrr)
			{
				bpf_copy_from_user(mrr, sizeof(MemoryRegion), section->mr);

				ramblock_ptr(mrr->ram_block, xlat, &temp_ptr,vq_id);
			}
			if (temp_ptr != NULL)
				*iov_base = temp_ptr;
		}
	}

	*len = xlen;
	return 0;
}

static __always_inline uint32_t virtqueue_map_desc(uint32_t vq_id,struct iovecc *iov, bool is_write, hwaddr pa, size_t sz, AddressSpace *dma_as)
{
	hwaddr *addr;
	uint32_t arrary_num = 0;
	hwaddr len = sz;

	dma_memory_map(dma_as, pa, &len, is_write ? DMA_DIRECTION_FROM_DEVICE : DMA_DIRECTION_TO_DEVICE,
				MEMTXATTRS_UNSPECIFIED, &iov->iov_base,vq_id);
	if(len!=sz)
	{
		bpf_printk("map error\n");
		return 1;
	}
	iov->iov_len = len;
	return 0;
}

static __always_inline uint16_t vring_avail_ring(uint32_t vq_id) // To get the head vring
{
	uint16_t head=0;
	uint32_t idx =0;
	struct VirtQueue *vq;
	struct MemoryRegionCache *desc;
	struct VRingDesc *vrdesc;
	VRMRCS *caches;
	vq = bpf_map_lookup_elem(&vq_map, &vq_id);
	if (vq)
	{
		idx = (vq->last_avail_idx) %vq->vring.num;
		hwaddr pa = offsetof(VRingAvail, ring[idx]);
		vring_get_region_caches(vq);
		caches = bpf_map_lookup_elem(&VRMRC, &vq_id);
		if (caches)
		{
			bpf_copy_from_user(&head, sizeof(uint16_t), (void *)(caches->avail.ptr + pa));
		}
		
	}
	
	return head;
}

static inline uint16_t vring_avail_idx(struct VirtQueue *vq,int vq_id)
{
	VRMRCS *caches;
	caches = bpf_map_lookup_elem(&VRMRC, &vq_id);
    hwaddr pa = offsetof(VRingAvail, idx);
	uint16_t shadow_avail_idx = 0;
	
    if (caches) {
		// barrier_bpf();
		bpf_copy_from_user(&shadow_avail_idx, sizeof(uint16_t), caches->avail.ptr+pa);
        
   		return shadow_avail_idx;
    }
	return 0;

}

static void vring_set_avail_event_pre(int num,  __u64 vq_addr)
{
	uint16_t shadow_avail_idx;
	__u64 pa;
	struct VirtQueue *vq;
	struct Useraddr *avail;
	VRMRCS *caches;
	int ret = 0;
	avail = bpf_map_lookup_elem(&avail_addr_map, &num);
	if(avail==NULL)
		return;
	vq = bpf_map_lookup_elem(&vq_map, &num);
	if(vq==NULL)
		return;
	caches = bpf_map_lookup_elem(&VRMRC, &num);
	if(caches==NULL)
		return;
	pa = offsetof(struct VirtQueue, shadow_avail_idx);
	avail->shadow_avail_idx = pa + vq_addr;
	avail->vring_used = caches->used.ptr;
	pa = offsetof(VRingUsed, ring[vq->vring.num]);

	avail->vring_used = avail->vring_used+ pa;


}
static void addr_write(__u64 addr,uint16_t num)
{
	#if !defined(DEBUG)
	bpf_uring_write_user(addr, &num, sizeof(uint16_t));
	#endif 
}
static __always_inline size_t
iov_to_buf(struct iovecc *iov,size_t offset, void *buf, size_t bytes)
{

	if ( offset <= iov->iov_base && bytes <= iov->iov_len- offset)
	{
		if (bpf_copy_from_user(buf,bytes,iov->iov_base + offset)<0)
		{
			bytes =  -1;
		}
		return bytes;
	}

	return 0;

}

static __always_inline size_t
iov_size(const struct iovecc *iov, const unsigned int iov_cnt)
{
    size_t len;
    unsigned int i;
    len = 0;
    for (i = 0; i < iov_cnt; i++) {
		if(i>256)
			break;
        len += iov[i].iov_len;
    }
    return len;
}



static uint32_t copy_vq(int num,  __u64 vq_addr)
{
	__u64 addr = vq_addr + num * 0x98;
	struct VirtQueue *vq;
	vq = bpf_map_lookup_elem(&vq_map, &num);
	if (vq)
	{
		bpf_copy_from_user(vq, sizeof(struct VirtQueue), (struct VirtQueue *)addr);
		vring_get_region_caches(vq);
	}
	return 0;
}
static void virtio_queue_set_notification(uint64_t vq_addr, bool enable)
{

	int ret;
	__u64 pa = offsetof(struct VirtQueue, notification);
	__u64 notification_addr = pa + vq_addr;

	#if !defined(DEBUG)
	ret = bpf_uring_write_user(notification_addr, &enable, sizeof(bool));
	#endif 
}

static uint32_t virtio_queue_empty_rcu( __u64 addr,uint32_t vq_id)
{
	

	struct VirtQueue *vq;
	uint32_t ret = 0;
	vq = bpf_map_lookup_elem(&vq_map, &vq_id);
	uint16_t shadow_avail_idx = 0;
	if (vq)
	{
		
		if(vq->shadow_avail_idx != (vq->last_avail_idx))
		{
			return 1;
		}

		// bpf_copy_from_user(vq, sizeof(struct VirtQueue), (struct VirtQueue *)(addr+vq_id*0*98));
		
		shadow_avail_idx =  vring_avail_idx(vq,vq_id);

		vq->shadow_avail_idx = shadow_avail_idx;
		 
		__u64 vq_addr = addr + vq_id * 0x98;
		__u64 pa = offsetof(struct VirtQueue, shadow_avail_idx);
		__u64 shadow_avail_idx_addr = pa + vq_addr;
		barrier_bpf();
		#if !defined(DEBUG)
		ret = bpf_uring_write_user(shadow_avail_idx_addr, &shadow_avail_idx, sizeof(uint16_t));
		#endif 
		#if defined(DEBUG)
		bpf_printk("vlast_avail_idx is %u, vq->shadow_avail_idx is %u\n",vq->last_avail_idx,vq->shadow_avail_idx);
		#endif 


		if(vq->shadow_avail_idx==vq->last_avail_idx)
		{
			
			return 0;
		}
		else
		{
			
			return 1;
		}
	}
}




static int desc_pop_sub(uint32_t index, void *ctxx)
{
	struct vec_pop_ctx *ctx;
	uint32_t num=0;
	int ret;
	ctx = (struct vec_pop_ctx *)ctxx;
	if(*ctx->rc==VIRTQUEUE_READ_DESC_MORE)
	{
		num = *ctx->out_num+*ctx->in_num+256*(*ctx->vq_id);
		ctx->desc = bpf_map_lookup_elem(&descs, &num);

		if(ctx->desc ==NULL)
			return 1;
		if (ctx->desc->flags & VRING_DESC_F_WRITE)
		{
			ret = virtqueue_map_desc(*ctx->vq_id,&ctx->result->iovec[*ctx->in_num + *ctx->out_num], true, ctx->desc->addr, ctx->desc->len, ctx->as);
			if(ret)
				return 1;
			*ctx->in_num = *ctx->in_num + 1;
		}
		else
		{
			if(*ctx->in_num)
			{

				bpf_printk("desc flags is %u\n",ctx->desc->flags );
				bpf_printk("head is %u\n",ctx->head);
				return 1;
			}
			ret = virtqueue_map_desc(*ctx->vq_id,&ctx->result->iovec[*ctx->out_num], false, ctx->desc->addr, ctx->desc->len, ctx->as);
			if(ret)
			{
				bpf_printk("map error\n");
				return 1;
			}
			*ctx->out_num = *ctx->out_num + 1;
		}
		if (!(ctx->desc->flags & VRING_DESC_F_NEXT))
		{
			*ctx->rc = VIRTQUEUE_READ_DESC_DONE;
			return 1;
		}

		*ctx->head = ctx->desc->next;
		if(ctx->desc_cache==NULL)
			return 1;
		vring_split_desc_read(ctx->desc_cache, *ctx->head,NULL,*ctx->vq_id,*ctx->out_num+*ctx->in_num);
		*ctx->rc = VIRTQUEUE_READ_DESC_MORE;		
		return 0;
	}
	else
		return 1;
}

static int virtqueue_split_pop(uint32_t index, void *ctxx)
{
	uint32_t out_num, in_num;
	uint32_t max;
	uint16_t cq_head;
	uint16_t head;
	uint32_t vq_id=0;
	uint64_t vq_addr;
	uint32_t num;
	// uint32_t type;
	hwaddr pa;
	int rc = 1;
	unsigned int i;
	int ret;
	struct VirtQueue *vq;
	struct VirtIODevice *vdev;
	struct AddressSpace *as;
	struct VRingDesc *desc,*descc;
	struct Useraddr *user;
	struct MemoryRegionCache *desc_cache;
	VRMRCS *vrmrc;
	Fast_map *result=NULL;
	struct req_pop_ctx *ctx;
	struct virtio_blk_outhdr *req_out;
	struct vec_pop_ctx pop_ctx;
	struct Useraddr *avail;
	struct io_uring_bpf_ctx *ctxxx = (struct io_uring_bpf_ctx *)ctxx;
	if(ctxx==NULL)
		goto error;

	vq_id =  ctxxx->vq_num;
	ctx = bpf_map_lookup_elem(&req_pop,&vq_id);
	if(ctx == NULL)
		return 1;
	
	vq_addr = ctx->vq_addr;
	
	ctx->req_num=virtio_queue_empty_rcu(vq_addr,vq_id);
	if(!ctx->req_num)
	{
		return 1;
		
	}
	out_num = in_num = max = 0;
	head = vring_avail_ring(vq_id);
	cq_head = head;
	
	
	i = head;
	

	vq = bpf_map_lookup_elem(&vq_map, &vq_id);
	if(vq==NULL)
		goto error;
	// bpf_printk("vq->vring.num is %u\n",vq->vring.num);
	num = (vq->last_avail_idx + 1)%vq->vring.num + vq_id*256;
	result = bpf_map_lookup_elem(&fast_map, &vq_id);
	if(result==NULL)
		goto error;
	user = bpf_map_lookup_elem(&User_addr_map, &num);
	if(user==NULL)
		goto error;
	__u64 addr = vq_addr + vq_id * 0x98;
	pa = offsetof(struct VirtQueue, last_avail_idx);
	user->last_avail_idx = pa + addr;
	pa = offsetof(struct VirtQueue, used_idx);
	user->used_idx = pa + addr;
	pa = offsetof(struct VirtQueue, shadow_avail_idx);
	user->shadow_avail_idx = pa + addr;
	vrmrc = bpf_map_lookup_elem(&VRMRC, &vq_id);
	if (vrmrc==NULL)
		goto error;
	// vring_set_avail_event(vq_id);

	// bpf_printk("vq->last_avail_idx is %u\n",vq->last_avail_idx);
	uint16_t last_avail_idx = vq->last_avail_idx + 1;
	#if !defined(DEBUG)
	ret = bpf_uring_write_user(user->last_avail_idx, &last_avail_idx, sizeof(uint16_t));
	#endif 
	vq->last_avail_idx = vq->last_avail_idx + 1;
	// DEBUG
	


	// vring_split_desc_read(&vrmrc->desc, i, NULL,vq_id,0);
	vring_split_desc_read_cache(&vrmrc->desc, i, NULL,vq_id);

	user->caches_used = vq->vring.caches;
	user->vring_used = vrmrc->used.ptr;

	
	pa = offsetof(VRingAvail, idx);
	user->avail_idx = vrmrc->avail.ptr+pa;
	vdev = bpf_map_lookup_elem(&VDEV, &vq_id);
	if(vdev==NULL)
		goto error;
	bpf_copy_from_user(vdev, sizeof(struct VirtIODevice), vq->vdev);
	pa = offsetof(struct VirtIODevice, isr);
	user->vdev_isr = (uint64_t)vq->vdev + pa;
	as = bpf_map_lookup_elem(&AS, &vq_id);
	// num = 0+vq_id*40;;
	// descc = bpf_map_lookup_elem(&descs, &num);
	descc = bpf_map_lookup_elem(&descs_cache, &vq_id);
	if (as == NULL || descc == NULL)
		goto error;
	// bpf_printk("descc len  is %lu,desc->addr is %lx,vq is %u\n",descc->len,desc->addr,vq_id);
	desc_cache = &vrmrc->desc;
	if(desc_cache == NULL)
		goto error;
	if(descc->flags && VRING_DESC_F_INDIRECT)
	{
		if(descc->addr==0)
		{
			bpf_printk("descc addr is %lu\n",descc->addr);
		}
		
		bpf_copy_from_user(as, sizeof(struct AddressSpace), vdev->dma_as);
		uint32_t len = address_space_cache_init(as, descc->addr, descc->len, false,vq_id);
		// if(len > 1000)
		// {
		// 	bpf_printk("len is %u\n",len);
		// }
		// bpf_printk(",descc addr is %lx,desc len is %u,desc flag is %u\n",descc->addr,descc->len,descc->flags);
		if (len < descc->len)
		{
			bpf_printk("address_space_cache_init ERROR,len is %u,desc len is %u,desc flag is %u,head is %u\n",len,descc->len,descc->flags,cq_head);
			goto error;
		}
		desc_cache = bpf_map_lookup_elem(&IDC, &vq_id);
		if (desc_cache)
		{
			max = descc->len / sizeof(struct VRingDesc);
			if(max >256)
			{
				bpf_printk("req is too larage, max is %u\n",max);
				goto error; 
			}
			// bpf_printk("descc->len is %u\n",descc->len);
			i = 0;
			ret = vring_split_desc_read_d(desc_cache, i, NULL,vq_id,0);
			if(ret < 0)
			{
				goto error;
			}
		}
		// if(max>100)
			// bpf_printk("max is %u \n",max);
		head = i;
		pop_ctx.result = result;
		pop_ctx.vq_id = &vq_id;
		pop_ctx.rc = &rc;
		pop_ctx.in_num = &in_num;
		pop_ctx.out_num = &out_num;
		pop_ctx.head = &head;
		pop_ctx.desc = desc;
		pop_ctx.as = as;
		pop_ctx.desc_cache = desc_cache;
		bpf_loop(max, desc_pop_sub, &pop_ctx, 0);

		if(in_num + out_num != max)
		{
			bpf_printk("pop error \n");
			bpf_printk("max is %u out is %u, in is %u\n",max, out_num, in_num);
			// bpf_printk("head is %u i is %u\n",*pop_ctx.head, i);
			// bpf_printk("descc len  is %lu,desc->addr is %lx\n",descc->len,desc->addr);
			// bpf_printk("desc len  is %lu,desc->addr is %lx\n",desc->len,desc->addr);
			goto error;
		}					
	}


	result->in_num = in_num;
	result->out_num = out_num;
	req_out = bpf_map_lookup_elem(&outhdr, &vq_id);
	if(req_out)
	{
		ret = iov_to_buf(&result->iovec[0],0,req_out,sizeof(struct virtio_blk_outhdr));
		if(ret!=sizeof(struct virtio_blk_outhdr))
		{
			goto error;
		}
		// type =;
		// if(type == 4)
		// {
		// 	// bpf_printk("flush command\n");
		// 	// goto error;
		// }
		result->type = req_out->type;
		result->offset = req_out->sector*512;
		
		result->wfd = vq->guest_notifier.wfd;
		// bpf_printk("vq is %d, \n", vq_id);
	}


	
	// ret = bpf_ringbuf_query(&kernel_ringbuf, BPF_RB_AVAIL_DATA);  
	// long ring_size = bpf_ringbuf_query(&kernel_ringbuf, BPF_RB_RING_SIZE);
	// long cons_pos = bpf_ringbuf_query(&kernel_ringbuf, BPF_RB_CONS_POS);
	// long prod_pos = bpf_ringbuf_query(&kernel_ringbuf, BPF_RB_PROD_POS);

	// bpf_printk("The avail_data is %u\n",ret);
	// num = last_avail_idx+ vq_id*256;
	result->id = num;
	user->vring_num = vq->vring.num; //used for compute the idx
	user->elem.id = cq_head;
	user->elem.len = iov_size(&result->iovec[1],out_num+in_num-1)-1;
	user->wfd = vq->guest_notifier.wfd;
	user->subreq_num = 0;
	// bpf_printk("result->id is %u,result->typeis %u, elem.id %u,elem.len is %u,iov count is %u\n",result->id,result->type,user->elem.id ,user->elem.len,out_num+in_num);
	bpf_map_update_elem(&User_addr_map, &num, user, BPF_ANY);

	
	


	// ctx->req_num = 0;
	// return 1;
	
	
	// bpf_printk("result->offset is %lx, request len is %d\n",result->offset,user->elem.len);
	// vq_id = result->id;
	// result->fd = 0XFFFF;
	// if(result->type==0)
	// {
	// 	uint64_t host_offset;
	// 	ret = qcow2_get_host_offset(result->offset,user->elem.len,&host_offset,ctxxx->L1Cache,ctxxx->L2Cache);
	// 	if(ret)
	// 		result->offset = host_offset;
	// }
	// else{

	// 	return 1;
	// }

	bpf_map_update_elem(&fast_map_d, &num, result, BPF_ANY);
	avail = bpf_map_lookup_elem(&avail_addr_map, &vq_id);
		if(avail==NULL)
			return 0;
	if(result->type==1)
	{

		addr_write(avail->vring_used,vq->last_avail_idx);
		#ifdef RAW
			ret = bpf_io_uring_submit(ctxxx,num,0,user->elem.len,NOTIFY);
		#else
		user->subreq_num = qcow2_co_pwritev_part(result->offset,user->elem.len,result,ctxxx,ctxxx->L1Cache,ctxxx->L2Cache,&fast_map_d,&User_addr_map,user);
		if(user->subreq_num<0)
		{
			 bpf_printk("qcow2_co_pwritev_part error!");
			last_avail_idx -= 1;
			ret = bpf_uring_write_user(user->last_avail_idx, &last_avail_idx, sizeof(uint16_t));
			goto error;
		}
		#endif
	}
	else if(result->type==0)
	{

		addr_write(avail->vring_used,vq->last_avail_idx);
		#ifdef RAW
			ret = bpf_io_uring_submit(ctxxx,num,0,user->elem.len,NOTIFY);
		#else
		user->subreq_num = qcow2_co_preadv_part(result->offset,user->elem.len,result,ctxxx,ctxxx->L1Cache,ctxxx->L2Cache,&fast_map_d,&User_addr_map,user);
		#endif
	}
	else  //qcow2 sync
	{

		// bpf_printk("sync requests, vq id is %u,last_avail_idx is %u!\n",vq_id,last_avail_idx);
		
		last_avail_idx -= 1;
		ret = bpf_uring_write_user(user->last_avail_idx, &last_avail_idx, sizeof(uint16_t));
		goto error;
		// #ifdef RAW
		// 	addr_write(avail->vring_used,vq->last_avail_idx);
		// 	ret = bpf_io_uring_submit(ctxxx,result->id,0,user->elem.len-1,0);
		// #else
		// 	#if !defined(DEBUG)
		// 	last_avail_idx -= 1;
		// 	ret = bpf_uring_write_user(user->last_avail_idx, &last_avail_idx, sizeof(uint16_t));
		// 	#endif
		// 	goto error;
		// #endif
	}

	// bpf_map_update_elem(&User_addr_map, &result->id, user, BPF_ANY);
	
	// bpf_map_update_elem(&fast_map_d, &result->id, result, BPF_ANY);

	
	
	// if(vq_id < 10000)
	// 	ret = bpf_io_uring_submit(ctxxx,vq_id);
	// 	bpf_printk("bpf_io_uring_submit ret is %d\n",ret);
	return 0;
error:
	ctx->error = -1;
	// bpf_printk("error\n");
	return 1;
}

// SEC("kprobe/io_pop_evo")
SEC("iouring")
int bpf_prog(struct io_uring_bpf_ctx *ctx)
{

	int ret;
	int req_num;
	// int *vq_idd = (void *)PT_REGS_PARM1(ctx);
	// struct io_ring_ctx *uring;
	// uring = ctx
	
	uint64_t vq_addr = ctx->vq_addr;
	struct req_pop_ctx *req_pop_ctx;
	uint32_t *router; 
	uint32_t *Qemurouter; 
	
	uint32_t vq_id=0;
	vq_id = ctx->vq_num;
	struct VirtQueue *vq;


	
	if(ctx->begin>0)
	{
		bpf_printk("ctx->begin is %u\n",ctx->begin);
		return 0;
	}
	//  return 0;
	// bpf_printk("********\n");
	
	req_pop_ctx = bpf_map_lookup_elem(&req_pop, &vq_id);
	if(req_pop_ctx == NULL)
		return 0;
	 
	
	// router = bpf_map_lookup_elem(&Router, &vq_id);
	// if(router == NULL)
	// 	return 0;
	// bpf_printk("vq is %u,router is %d, ctx addr is \n",vq_id,*router,(uint64_t)ctx);
	// return 0;
	copy_vq(vq_id, vq_addr);
	vring_set_avail_event_pre(vq_id, vq_addr);
	virtio_queue_set_notification(vq_id,1);


	req_pop_ctx->vq_id = vq_id;
	req_pop_ctx->error = 1;
	req_pop_ctx->vq_addr = vq_addr;
	req_pop_ctx->ctx = ctx;
	
	bpf_loop(256, virtqueue_split_pop, ctx, 0);
	virtio_queue_set_notification(vq_id,0);
	req_pop_ctx = bpf_map_lookup_elem(&req_pop, &vq_id);
	if(req_pop_ctx == NULL)
		return 0;

	vq = bpf_map_lookup_elem(&vq_map, &vq_id);
	if(vq==NULL)
		return 0;
	
	#if defined(DEBUG)
		ctx->qemu_router = 0;
		return 0;
	#endif 

	ctx->qemu_router = 0;
	if(req_pop_ctx->error<0){
		// *router =0;
		ctx->qemu_router = 0;
		// bpf_printk("interupted! error is %u\n",*router);
		// bpf_map_update_elem(&Router, &vq_id, router, BPF_ANY);
		goto error;
	}
	else
	{
		
		// bpf_printk("skip the qemu\n");
		ctx->qemu_router = 1;
	}

	return 0;
	
error:
	// bpf_printk("*****************\n");
	return 0;
			
}


SEC("kprobe/__kvm_io_bus_write")
int bpf_prog_count(struct pt_regs *ctx)
{
	struct kvm_io_range *range = (void *)PT_REGS_PARM3(ctx);
	uint64_t addr = _(range->addr);
	uint32_t *count;
	uint32_t map_id;
	map_id = 0;
	
	if (addr >= 0xfe003000 && addr <= 0xfe003058)
	{
		count = bpf_map_lookup_elem(&exit_count, &map_id);
		if(count)
		{
			*count = *count + 1;
			bpf_printk("count is %u \n",*count);
		}

	}

}

SEC("iouring")
int iourng_prog(struct io_uring_bpf_ctx *ctx)
{
	bpf_printk("req_pop, io_uring register successs");
	uint64_t vq_addr = ctx->vq_addr;
	uint32_t vq_id;
	bpf_printk("addr is %lx\n",vq_addr);
	vq_id =100;

	// bpf_io_uring_submit(ctx,vq_id);
	return 0;
}
char _license[] SEC("license") = "GPL";
