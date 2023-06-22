#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/types.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include "help.c"
#include "vmlinux.h"
#include "int128.h"
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct VirtQueue);
	__uint(max_entries, 1);
} vq_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct VRingDesc);
	__uint(max_entries, 256);
} descs SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct VRMRC);
	__uint(max_entries, 1);
} VRMRC SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct MemoryRegionCache);
	__uint(max_entries, 1);
} MRC SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct VirtIODevice);
	__uint(max_entries, 1);
} VDEV SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct AddressSpace);
	__uint(max_entries, 1);
} AS SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct MemoryRegionCache);
	__uint(max_entries, 1);
} IDC SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct flatview);
	__uint(max_entries, 1);
} Cache_FLATV SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct AddressSpaceDispatch);
	__uint(max_entries, 1);
} Dispatch SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct MemoryRegionSection);
	__uint(max_entries, 1);
} Dispatch_MRU SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, Node);
	__uint(max_entries, 1);
} Dispatch_M_Node SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct MemoryRegionSection);
	__uint(max_entries, 2);
} Dispatch_M_Sec SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct MemoryRegionSection);
	__uint(max_entries, 1);
} MRS SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, MemoryRegion);
	__uint(max_entries, 1);
} MR SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, RAMBlock);
	__uint(max_entries, 1);
} RB SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, struct iovec);
	__uint(max_entries, 3);
} IOVECS SEC(".maps");
struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, hwaddr);
	__uint(max_entries, 3);
} ADDRS SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, Fast_map);
	__uint(max_entries, 1);
} fast_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, uint32_t);
	__type(value, Useraddr);
	__uint(max_entries, 1);
} User_addr_map SEC(".maps");

static inline void ramblock_ptr(RAMBlock *block, ram_addr_t offset, ram_addr_t *ptr)
{
	RAMBlock *rb;
	uint32_t arrary_num = 0;

	rb = bpf_map_lookup_elem(&RB, &arrary_num);
	if (rb)
	{
		bpf_copy_from_user(rb, sizeof(MemoryRegion), block);
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

static __always_inline bool memory_region_is_ram(MemoryRegion *mr)
{
	MemoryRegion *mrr;
	uint32_t arrary_num = 0;
	mrr = bpf_map_lookup_elem(&MR, &arrary_num);
	if (mrr)
	{
		bpf_copy_from_user(mrr, sizeof(MemoryRegion), mr);
		return mrr->ram;
	}
}
static inline bool memory_access_is_direct(MemoryRegion *mr, bool is_write)
{
	MemoryRegion *mrr;
	uint32_t arrary_num = 0;
	mrr = bpf_map_lookup_elem(&MR, &arrary_num);
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
}

static __always_inline uint32_t phys_page_find(AddressSpaceDispatch *d, hwaddr addr)
{
	PhysPageEntry lp = d->phys_map, *p, *temp;
	uint32_t arrary_num = 0;
	Node *nodes;
	struct MemoryRegionSection *section, *section1;
	hwaddr index = addr >> TARGET_PAGE_BITS;
	nodes = bpf_map_lookup_elem(&Dispatch_M_Node, &arrary_num);
	section = bpf_map_lookup_elem(&Dispatch_M_Sec, &arrary_num);
	int i, t = 20;
	if (nodes && section)
	{

		bpf_copy_from_user(nodes, sizeof(Node), d->map.nodes);
		temp = nodes;
		// for (i=0; i<20;i++)
		// {
		// 	bpf_printk("node **** skip is %u: ptr is %u\n", temp[i].skip,temp[i].ptr);
		// }

		for (i = P_L2_LEVELS; t && lp.skip && (i -= lp.skip) >= 0; t--)
		{
			// bpf_printk("lp skip is 0x%x: ptr is 0x%x\n", lp.skip,lp.ptr);
			if (lp.ptr == PHYS_MAP_NODE_NIL)
			{

				bpf_copy_from_user(section, sizeof(struct MemoryRegionSection), &d->map.sections[0]);
				// bpf_printk("section regin is %lu: address is %lu\n", section->offset_within_region, section->offset_within_address_space);
				return 0;
			}
			bpf_copy_from_user(nodes, sizeof(Node), d->map.nodes[lp.ptr]);
			// p = &temp[lp.ptr];
			p = nodes;
			// bpf_printk("step 1 p skip is %u: ptr is %u\n", p->skip,p->ptr);
			lp = p[(index >> (i * P_L2_BITS)) & (P_L2_SIZE - 1)];
			// bpf_printk("step 2 lp skip is %u: ptr is %u\n", lp.skip,lp.ptr);
		}
		section = bpf_map_lookup_elem(&Dispatch_M_Sec, &arrary_num);
		arrary_num = 1;
		section1 = bpf_map_lookup_elem(&Dispatch_M_Sec, &arrary_num);
		if (section && section1)
		{
			bpf_copy_from_user(section1, sizeof(struct MemoryRegionSection), &d->map.sections[lp.ptr]);
			if (section_covers_addr(section1, addr))
			{
				// bpf_printk("section1 regin is %lu: address is %lu\n", section1->offset_within_region, section1->offset_within_address_space);
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

static __always_inline uint32_t address_space_lookup_region(AddressSpaceDispatch *d, struct MemoryRegionSection *section, hwaddr addr, bool resolve_subpage)
{
	uint32_t arrary_num = 0;
	uint32_t ret = 0;
	struct MemoryRegionSection *section1;
	subpage_t *subpage;
	section1 = section;
	// bpf_printk("mru_section addr is %lx: map is %lx\n", d->mru_section, d->map.sections);
	if (!section_covers_addr(section, addr) || !section || d->mru_section == d->map.sections)
	{

		ret = phys_page_find(d, addr);
		section1 = bpf_map_lookup_elem(&Dispatch_M_Sec, &ret);
		if (section1)
		{
			bpf_map_update_elem(&Dispatch_MRU, &arrary_num, section1, BPF_ANY);
			// bpf_probe_write_user(d->mru_section,section1,sizeof(struct MemoryRegionSection));
		}
		return ret;
	}
	bpf_map_update_elem(&Dispatch_M_Sec, &arrary_num, section, BPF_ANY);
	return ret;
	// if (resolve_subpage && section1->mr->subpage) {
	//     subpage = container_of(section->mr, subpage_t, iomem);
	//     // section = &d->map.sections[subpage->sub_section[SUBPAGE_IDX(addr)]];
	// }
}

static __always_inline int address_space_translate_internal(AddressSpaceDispatch *d, hwaddr addr, hwaddr *xlat,
															hwaddr *plen, bool resolve_subpage)
{
	uint32_t arrary_num = 0, ret;
	struct MemoryRegionSection *section;
	Int128 diff;
	section = bpf_map_lookup_elem(&Dispatch_MRU, &arrary_num);
	if (section)
	{

		bpf_copy_from_user(section, sizeof(struct MemoryRegionSection), d->mru_section);
		ret = address_space_lookup_region(d, section, addr, resolve_subpage);

		section = bpf_map_lookup_elem(&Dispatch_M_Sec, &ret);

		if (section)
		{
			// bpf_printk("section regin is %lu: address is %lu\n", section->offset_within_region, section->offset_within_address_space);
			addr -= section->offset_within_address_space;
			*xlat = addr + section->offset_within_region;

			if (memory_region_is_ram(section->mr))
			{
				diff = int128_sub(section->size, int128_make64(addr));
				*plen = int128_get64(int128_min(diff, int128_make64(*plen)));
			}
			// bpf_printk("xlat is %lu, plen is %u\n",*xlat,*plen);
			return ret;
		}
	}
}

static __always_inline uint32_t address_space_cache_init(AddressSpace *as,
														 hwaddr addr,
														 hwaddr len,
														 bool is_write)
{
	struct MemoryRegionCache *i_desc_cache;
	struct flatview *view;
	struct AddressSpaceDispatch *d;
	struct MemoryRegionSection *section;
	MemoryRegion *mrr;
	uint32_t arrary_num = 0, ret = 0;
	hwaddr l;
	Int128 diff;
	l = len;
	i_desc_cache = bpf_map_lookup_elem(&IDC, &arrary_num);
	view = bpf_map_lookup_elem(&Cache_FLATV, &arrary_num);
	d = bpf_map_lookup_elem(&Dispatch, &arrary_num);
	if (i_desc_cache && d && view)
	{
		bpf_copy_from_user(view, sizeof(struct flatview), as->current_map);
		bpf_copy_from_user(d, sizeof(struct AddressSpaceDispatch), view->dispatch);
		ret = address_space_translate_internal(d, addr, &i_desc_cache->xlat, &l, true);

		if (ret == 1)
		{
			arrary_num = 1;
		}
		section = bpf_map_lookup_elem(&Dispatch_M_Sec, &arrary_num);
		if (section)
		{
			diff = int128_sub(section->size, int128_make64(i_desc_cache->xlat - section->offset_within_region));
			l = int128_get64(int128_min(diff, int128_make64(l)));

			if (memory_access_is_direct(section->mr, is_write))
			{
				arrary_num = 0;
				mrr = bpf_map_lookup_elem(&MR, &arrary_num);
				if (mrr)
				{
					ramblock_ptr(mrr->ram_block, i_desc_cache->xlat, &i_desc_cache->ptr);
				}
			}
			else
			{
				i_desc_cache->ptr = NULL;
			}
			i_desc_cache->len = l;
			i_desc_cache->is_write = is_write;
			return l;
		}
	}
}

static __always_inline uint32_t vring_split_desc_read(struct MemoryRegionCache *desc_cache, uint32_t head_num, uint32_t *ret) // To get the head vring
{
	struct VRingDesc *vrdesc;
	// bpf_printk("Head is %u\n", head_num);

	vrdesc = bpf_map_lookup_elem(&descs, &head_num);
	if (vrdesc)
	{
		bpf_copy_from_user(vrdesc, sizeof(struct VRingDesc), desc_cache->ptr + head_num * sizeof(struct VRingDesc));
		if (ret != NULL)
		{
			*ret = vrdesc->next;
		}
		// bpf_printk("VRing Desc addr is %lu: len is %u, next is %u\n", vrdesc->addr, vrdesc->len, vrdesc->next);
		// bpf_printk("VRing Desc flag is %u\n", vrdesc->flags);
	}
	// head_num++;
}
static __always_inline uint16_t vring_get_region_caches(struct VirtQueue *vq) //
{
	int ret = 0;
	struct VRMRC *caches;
	caches = bpf_map_lookup_elem(&VRMRC, &ret);
	if (caches)
	{
		bpf_copy_from_user(caches, sizeof(struct VRMRC), vq->vring.caches);
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
										MemTxAttrs attrs)
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
	d = bpf_map_lookup_elem(&Dispatch, &arrary_num);
	if (d)
	{
		bpf_copy_from_user(d, sizeof(AddressSpaceDispatch), fv->dispatch);

		ret = address_space_translate_internal(d, addr, xlat, plen_out, is_mmio);

		return ret;
	}
}

static inline int flatview_translate(flatview *fv, hwaddr addr, hwaddr *xlat,
									 hwaddr *plen, bool is_write,
									 MemTxAttrs attrs)
{
	int ret = 0;
	ret = flatview_do_translate(fv, addr, xlat, plen, NULL,
								is_write, true, attrs);

	return ret;
}

static inline ram_addr_t *dma_memory_map(AddressSpace *dma_as, dma_addr_t addr, dma_addr_t *len,
										 DMADirection dir, MemTxAttrs attrs, ram_addr_t *iov_base)
{
	hwaddr xlen = *len;
	uint32_t arrary_num = 0;
	hwaddr l, xlat, temp;
	flatview *fv;
	MemoryRegionSection *section;
	MemoryRegion *mrr;
	void *temp_ptr = NULL;
	int ret = 0;
	l = xlen;
	fv = bpf_map_lookup_elem(&Cache_FLATV, &arrary_num);
	if (fv)
	{
		bpf_copy_from_user(fv, sizeof(struct flatview), dma_as->current_map);
		ret = flatview_translate(fv, addr, &xlat, &l, dir == DMA_DIRECTION_FROM_DEVICE, attrs);
		if (ret == 1)
		{
			arrary_num = 1;
		}
		section = bpf_map_lookup_elem(&Dispatch_M_Sec, &arrary_num);
		if (section)
		{
			// bpf_printk("section ret is %d,regin is %lu\n: address is %lu\n",arrary_num, section->offset_within_region, section->offset_within_address_space);
			// bpf_printk("xlen is %lu, l is %lu\n",xlen,l);
			arrary_num = 0;
			mrr = bpf_map_lookup_elem(&MR, &arrary_num);
			if (mrr)
			{
				bpf_copy_from_user(mrr, sizeof(MemoryRegion), section->mr);

				ramblock_ptr(mrr->ram_block, xlat, &temp_ptr);
			}
			if (temp_ptr != NULL)
				*iov_base = temp_ptr;
		}
	}

	*len = xlen;
}
static inline void virtqueue_map_desc(VirtIODevice *vdev, unsigned int p_num_sg,
									  bool is_write, hwaddr pa, size_t sz, AddressSpace *dma_as)
{
	hwaddr *addr;
	struct iovec *iov;
	uint32_t arrary_num = 0, k;
	unsigned num_sg = p_num_sg;

	k = 2;
	// while(sz&&k>0)
	// {
	iov = bpf_map_lookup_elem(&IOVECS, &num_sg);
	addr = bpf_map_lookup_elem(&ADDRS, &num_sg);
	if (iov && addr)
	{
		hwaddr len = sz;

		dma_memory_map(dma_as, pa, &len, is_write ? DMA_DIRECTION_FROM_DEVICE : DMA_DIRECTION_TO_DEVICE,
					   MEMTXATTRS_UNSPECIFIED, &iov->iov_base);
		iov->iov_len = len;
		*addr = pa;
		num_sg++;
		// sz -= len;
		// pa += len;
		// k--;
	}
	// }
}

static __always_inline uint16_t vring_avail_ring() // To get the head vring
{
	uint16_t head;

	struct VirtQueue *vq;
	struct MemoryRegionCache *desc;
	struct VRingDesc *vrdesc;
	struct VRMRC *caches;
	int ret = 0;
	vq = bpf_map_lookup_elem(&vq_map, &ret);
	if (vq)
	{
		uint32_t idx = vq->last_avail_idx % vq->vring.num;
		hwaddr pa = offsetof(VRingAvail, ring[idx]);
		vring_get_region_caches(vq);
		caches = bpf_map_lookup_elem(&VRMRC, &ret);
		if (caches)
		{
			bpf_copy_from_user(&head, sizeof(uint16_t), (void *)(caches->avail.ptr + pa));
		}

		// bpf_probe_write_user((void *)(caches.avail.ptr+pa),&head, sizeof(uint16_t));
		// last_avail_idx -= 1;
		// bpf_probe_write_user(&vq->last_avail_idx,&last_avail_idx, sizeof(uint16_t));
	}

	return head;
}

static __always_inline bool copy_vq(int num, __u64 *idx, __u64 *used, __u64 *ava_idx)
{
	__u64 vq_addr = 0x55A2E2364170;

	__u64 addr = vq_addr + num * 0x98;
	uint32_t ret = 0;
	__u16 lastavailidx;
	struct VirtQueue *vq;
	vq = bpf_map_lookup_elem(&vq_map, &ret);

	if (vq)
	{
		bpf_copy_from_user(vq, sizeof(struct VirtQueue), (struct VirtQueue *)addr);

		hwaddr pa = offsetof(struct VirtQueue, last_avail_idx);
		*idx = pa + addr;
		pa = offsetof(struct VirtQueue, used_idx);
		*used = pa + addr;
		pa = offsetof(struct VirtQueue, shadow_avail_idx);
		*ava_idx = pa + addr;
	}

	return 0;
}

static inline uint16_t vring_avail_idx(struct VirtQueue *vq)
{
	struct VRMRC *caches;
	uint32_t arr_num;
	arr_num = 0;
	caches = bpf_map_lookup_elem(&VRMRC, &arr_num);
    hwaddr pa = offsetof(VRingAvail, idx);
	uint16_t shadow_avail_idx;

    if (caches) {
		bpf_copy_from_user(&shadow_avail_idx, sizeof(uint16_t), caches->avail.ptr+pa);
        
   		return shadow_avail_idx;
    }
	else
	{
		return 0;
	}


}

static __always_inline void vring_set_avail_event(struct VirtQueue *vq, struct Useraddr *user)
{
	uint16_t shadow_avail_idx;
	int ret = 0;
	shadow_avail_idx = vring_avail_idx(vq);
	if(shadow_avail_idx!=0)
	{
		ret = bpf_probe_write_user(user->shadow_avail_idx, &shadow_avail_idx, sizeof(uint16_t));
		if(ret<0)
		{
			bpf_printk("set shadow_avail_idx failure\n");
		}
	}
}

SEC("kprobe/__kvm_io_bus_write")
int bpf_prog(struct pt_regs *ctx)
{

	int dev_count;
	int ioeventfd_count;
	__u64 addr;
	__u64 *add;
	int len;
	int ret;
	int rc = 1;
	int arr_num = 0;
	unsigned int max, i;
	struct kvm_io_bus *bus = (void *)PT_REGS_PARM2(ctx);
	struct kvm_io_range *range = (void *)PT_REGS_PARM3(ctx);
	dev_count = _(bus->dev_count);
	ioeventfd_count = _(bus->ioeventfd_count);
	addr = _(range->addr);
	len = _(range->len);
	struct VRMRC *vrmrc;
	struct VirtQueue *vq;
	struct VirtIODevice *vdev;
	struct AddressSpace *as;
	struct VRingDesc *desc;
	struct iovec *iov;
	struct Useraddr *user;
	struct MemoryRegionCache *desc_cache;
	Fast_map *result;
	unsigned out_num, in_num, elem_entries;
	out_num = in_num = elem_entries = 0;
	uint32_t hd;
	
	result = bpf_map_lookup_elem(&fast_map, &arr_num);
	user = bpf_map_lookup_elem(&User_addr_map, &arr_num);

	if (result && user)
	{
		if (addr >= 0xfe003000 && addr <= 0xfe00301c)
		{
			ret = (addr - 0xfe003000) / 4;
			// get the vq to be operated

			//also save the last_avail_idx and used_idx addr used to update
			copy_vq(ret, &user->last_avail_idx, &user->used_idx, &user->shadow_avail_idx);
			// copy the desc from the head vring
			uint16_t head = vring_avail_ring();
			
			result->head = head;
			vrmrc = bpf_map_lookup_elem(&VRMRC, &arr_num);
			if (vrmrc)
			{
				vring_split_desc_read(&vrmrc->desc, head, NULL);
			}

			// translate the address
			vq = bpf_map_lookup_elem(&vq_map, &arr_num);

			if (vq&&vrmrc)
			{



				//save the caches used addr used to update used elem
				user->caches_used = vq->vring.caches;
				user->vring_used = vrmrc->used.ptr;

				vdev = bpf_map_lookup_elem(&VDEV, &arr_num);
				if (vdev)
				{
					bpf_copy_from_user(vdev, sizeof(struct VirtIODevice), vq->vdev);

					//save the isr addr used to update
					hwaddr pa = offsetof(struct VirtIODevice, isr);
					user->vdev_isr = (uint64_t)vq->vdev + pa;
					// bpf_printk("user->vdev addr is %lx, pa is %lx, isr addr is %lx\n", vq->vdev, pa,user->vdev_isr);
					as = bpf_map_lookup_elem(&AS, &arr_num);
					desc = bpf_map_lookup_elem(&descs, &head);
					if (as && desc)
					{
						bpf_copy_from_user(as, sizeof(struct AddressSpace), vdev->dma_as);
						uint32_t len = address_space_cache_init(as, desc->addr, desc->len, false);

						if (len < desc->len)
						{
							bpf_printk("ERROR\n");
							return 0;
						}

						desc_cache = bpf_map_lookup_elem(&IDC, &arr_num);
						if (desc_cache)
						{
							max = desc->len / sizeof(struct VRingDesc);
							i = 0;
							vring_split_desc_read(desc_cache, i, NULL);
							head = 0;

							for (i = 0; i < 4; i++)
							{
								desc = bpf_map_lookup_elem(&descs, &head);
								if (desc)
								{
									if (desc->flags & VRING_DESC_F_WRITE)
									{
										virtqueue_map_desc(vdev, in_num + out_num, true, desc->addr, desc->len, as);
										in_num++;
									}
									else
									{
										virtqueue_map_desc(vdev, out_num, false, desc->addr, desc->len, as);
										out_num++;
									}
									if (!(desc->flags & VRING_DESC_F_NEXT))
									{
										break;
									}
									head = desc->next;
									vring_split_desc_read(desc_cache, head, &hd);
								}
							}
						}
					}
				}
				int ii = 0;
				iov = bpf_map_lookup_elem(&IOVECS, &ii);
				add = bpf_map_lookup_elem(&ADDRS, &ii);
				if (iov && add)
				{
					result->iovec[0].iov_base = iov->iov_base;
					result->iovec[0].iov_len = iov->iov_len;
					result->addr[0] = *add;
					// bpf_printk("iov base is %lx: len is %u\n", result->iovec[0].iov_base, iov->iov_len);
				}
				ii = 1;
				iov = bpf_map_lookup_elem(&IOVECS, &ii);
				add = bpf_map_lookup_elem(&ADDRS, &ii);
				if (iov && add)
				{
					result->iovec[1].iov_base = iov->iov_base;
					result->iovec[1].iov_len = iov->iov_len;
					// if (iov->iov_len == 512)
					// 	result->fd = 22;
					// else
					// {
					// 	result->fd = 0;
					// 	return 0;
					// }

					result->addr[1] = *add;
					bpf_printk("iov base is %lx: len is %u\n", result->iovec[1].iov_base, iov->iov_len);
				}
				ii = 2;
				iov = bpf_map_lookup_elem(&IOVECS, &ii);
				add = bpf_map_lookup_elem(&ADDRS, &ii);
				if (iov && add)
				{
					result->iovec[2].iov_base = iov->iov_base;
					result->iovec[2].iov_len = iov->iov_len;
					result->addr[2] = *add;
					bpf_printk("iov base is %lx: len is %u\n", result->iovec[2].iov_base, iov->iov_len);
				}
				result->fd = 0;
				result->wfd = vq->guest_notifier.wfd;

				
			}
		}
		else
		{
			result->fd = 0;
		}

		return 0;
	}
}

static __always_inline uint16_t vring_used_idx_set(struct Useraddr *user, uint16_t val) //
{
	int ret = 0;
	struct VRMRC *caches;
	caches = bpf_map_lookup_elem(&VRMRC, &ret);
	bpf_printk("the vring_used addr is %lx, used_idx is %lx", user->vring_used , user->used_idx);
	if (caches)
	{
		if (caches->used.len != 0)
		{
			hwaddr pa = offsetof(VRingUsed, flags);
			ret = bpf_probe_write_user(user->vring_used + pa, &val, sizeof(val));
			if(ret<0)
			{
				bpf_printk("update the vring used_idxerror!\n");
			}
			
		}
		ret = bpf_probe_write_user(user->used_idx, &val, sizeof(val));
		if(ret<0)
		{
			bpf_printk("update the vring used_idxerror!\n");
		}
	}

	return 0;
}
static __always_inline uint16_t virtio_set_isr(struct VirtIODevice *vdev,struct Useraddr *user, uint8_t value) //
{
	uint8_t old = vdev->isr;
	int ret;
	if ((old & value) != value)
	{
		ret = bpf_probe_write_user(user->vdev_isr, &value, sizeof(uint8_t));
		if(ret<0)
		{
			bpf_printk("update the vring used_idxerror!\n");
		}
	}

}

SEC("kretprobe/__kvm_io_bus_write")
int bpf_get_idx_ret(struct pt_regs *ctx)
{
	unsigned int arr_num;
	int ret;
	struct VirtQueue *vq;
	Fast_map *result;
	struct VRMRC *caches;
	VRingUsedElem uelem;
	struct VirtIODevice *vdev;
	struct Useraddr *user;
	uint16_t new;
	arr_num = 0;
	unsigned int idx;
	uint16_t last_avail_idx;
	int off = (int)PT_REGS_RC(ctx);
	vq = bpf_map_lookup_elem(&vq_map, &arr_num);
	result = bpf_map_lookup_elem(&fast_map, &arr_num);
	caches = bpf_map_lookup_elem(&VRMRC, &arr_num);
	vdev = bpf_map_lookup_elem(&VDEV, &arr_num);
	user = bpf_map_lookup_elem(&User_addr_map, &arr_num);
	
	if (vq && result && user && vdev)
	{
		// bpf_printk("vq used idx is %u\n", vq->used_idx);
		bpf_printk("ret  is %u\n", off);
		if (off == 1111)
		{
			last_avail_idx = vq->last_avail_idx + 1;
			ret = bpf_probe_write_user(user->last_avail_idx, &last_avail_idx, sizeof(uint16_t));
			// bpf_printk("user->last_avail_idx is %u,addr is %lx\n", last_avail_idx, user->last_avail_idx);
			if(ret<0)
			{
				bpf_printk("update the last_avail_idx error!\n");
			}
			vring_set_avail_event(vq,user);

			bpf_printk("ret back!\n");
			idx = vq->used_idx % vq->vring.num;
			uelem.id = result->head;
			uelem.len = 578;
			hwaddr pa = offsetof(VRingUsed, ring[idx]);
			ret = bpf_probe_write_user(user->vring_used + pa, &uelem, sizeof(VRingUsedElem));
			if(ret<0)
			{
				bpf_printk("update the vring used_idxerror!\n");
			}
			bpf_printk("user->vring_used addr is %lx, pa is %lu\n", user->vring_used, pa);
			new = vq->used_idx + 1;
			vring_used_idx_set(user, new);

			virtio_set_isr(vdev,user, 0x1);
		}
		// else
		// {
		// 	bpf_printk("used_idx addr is %lx, last_avail_idx addr is %lx, \
		// 		caches_used addr is %lx\n", \
		// 		user->used_idx, user->last_avail_idx,user->caches_used);
		// }
	}
	return 0;
}
char _license[] SEC("license") = "GPL";
