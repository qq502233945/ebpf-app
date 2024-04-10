#ifndef __OPENRISC_VMLINUX_H_
#define __OPENRISC_VMLINUX_H_

#include <stdbool.h>

// #define DEBUG
#define RAW

#if defined(DEBUG)
#define NOTIFY 0
#else
#define NOTIFY 1
#endif

typedef struct AdapterInfo AdapterInfo;
typedef struct AddressSpace AddressSpace;
typedef struct AddrRange AddrRange;
typedef struct AioContext AioContext;
typedef struct Aml Aml;
typedef struct AnnounceTimer AnnounceTimer;
typedef struct ArchCPU ArchCPU;
typedef struct BdrvDirtyBitmap BdrvDirtyBitmap;
typedef struct BdrvDirtyBitmapIter BdrvDirtyBitmapIter;
typedef struct BlockBackend BlockBackend;
typedef struct BlockBackendRootState BlockBackendRootState;
typedef struct BlockDriverState BlockDriverState;
typedef struct BusClass BusClass;
typedef struct BusState BusState;
typedef struct Chardev Chardev;
typedef struct Clock Clock;
typedef struct CompatProperty CompatProperty;
typedef struct CoMutex CoMutex;
typedef struct ConfidentialGuestSupport ConfidentialGuestSupport;
typedef struct CPUAddressSpace CPUAddressSpace;
typedef struct CPUArchState CPUArchState;
typedef struct CPUJumpCache CPUJumpCache;
typedef struct CPUState CPUState;
typedef struct CPUTLBEntryFull CPUTLBEntryFull;
typedef struct DeviceListener DeviceListener;
typedef struct DeviceState DeviceState;
typedef struct DirtyBitmapSnapshot DirtyBitmapSnapshot;
typedef struct DisplayChangeListener DisplayChangeListener;
typedef struct DriveInfo DriveInfo;
typedef struct Error Error;
typedef struct EventNotifier EventNotifier;
typedef struct FlatRange FlatRange;
typedef struct flatview flatview;
typedef struct FWCfgEntry FWCfgEntry;
typedef struct FWCfgIoState FWCfgIoState;
typedef struct FWCfgMemState FWCfgMemState;
typedef struct FWCfgState FWCfgState;
typedef struct HostMemoryBackend HostMemoryBackend;
typedef struct I2CBus I2CBus;
typedef struct I2SCodec I2SCodec;
typedef struct IOMMUMemoryRegion IOMMUMemoryRegion;
typedef struct ISABus ISABus;
typedef struct ISADevice ISADevice;
typedef struct IsaDma IsaDma;
typedef struct JSONWriter JSONWriter;
typedef struct MACAddr MACAddr;
typedef struct MachineClass MachineClass;
typedef struct MachineState MachineState;
typedef struct MemoryListener MemoryListener;
typedef struct MemoryMappingList MemoryMappingList;

typedef struct MemoryRegion MemoryRegion;
typedef struct MemoryRegionCache MemoryRegionCache;
typedef struct MemoryRegionIoeventfd MemoryRegionIoeventfd;
typedef struct MemoryRegionSection MemoryRegionSection;
typedef struct MemoryRegionOps MemoryRegionOps;
typedef struct MigrationIncomingState MigrationIncomingState;
typedef struct MigrationState MigrationState;
typedef struct Monitor Monitor;
typedef struct MonitorDef MonitorDef;
typedef struct MSIMessage MSIMessage;
typedef struct NetClientState NetClientState;
typedef struct NetFilterState NetFilterState;
typedef struct NICInfo NICInfo;
typedef struct NodeInfo NodeInfo;
typedef struct NumaNodeMem NumaNodeMem;
typedef struct Object Object;
typedef struct ObjectClass ObjectClass;
typedef struct PCIBridge PCIBridge;
typedef struct PCIBus PCIBus;
typedef struct PCIDevice PCIDevice;
typedef struct PCIEAERErr PCIEAERErr;
typedef struct PCIEAERLog PCIEAERLog;
typedef struct PCIEAERMsg PCIEAERMsg;
typedef struct PCIESriovPF PCIESriovPF;
typedef struct PCIESriovVF PCIESriovVF;
typedef struct PCIEPort PCIEPort;
typedef struct PCIESlot PCIESlot;
typedef struct PCIExpressDevice PCIExpressDevice;
typedef struct PCIExpressHost PCIExpressHost;
typedef struct PCIHostDeviceAddress PCIHostDeviceAddress;
typedef struct PCIHostState PCIHostState;
typedef struct PhysPageEntry PhysPageEntry;
typedef struct PostcopyDiscardState PostcopyDiscardState;
typedef struct Property Property;
typedef struct PropertyInfo PropertyInfo;
typedef struct ObjectFree ObjectFree;
typedef struct QBool QBool;
typedef struct QDict QDict;
typedef struct QEMUBH QEMUBH;
typedef struct QemuConsole QemuConsole;
typedef struct QEMUFile QEMUFile;
typedef struct QemuLockable QemuLockable;
typedef struct QemuMutex QemuMutex;
typedef struct QemuOpt QemuOpt;
typedef struct QemuOpts QemuOpts;
typedef struct QemuOptsList QemuOptsList;
typedef struct QEMUSGList QEMUSGList;
typedef struct QemuSpin QemuSpin;
typedef struct QEMUTimer QEMUTimer;
typedef struct QEMUTimerListGroup QEMUTimerListGroup;
typedef struct QList QList;
typedef struct QNull QNull;
typedef struct QNum QNum;
typedef struct QObject QObject;
typedef struct QString QString;
typedef struct RAMBlock RAMBlock;
typedef struct RamDiscardManager RamDiscardManager;
typedef struct Range Range;
typedef struct ReservedRegion ReservedRegion;
typedef struct SavedIOTLB SavedIOTLB;
typedef struct SHPCDevice SHPCDevice;
typedef struct SSIBus SSIBus;
typedef struct TranslationBlock TranslationBlock;
typedef struct VirtIODevice VirtIODevice;
typedef struct Visitor Visitor;
typedef struct VMChangeStateEntry VMChangeStateEntry;
typedef struct VMStateDescription VMStateDescription;
typedef struct DumpState DumpState;
typedef struct RAMBlockNotifier RAMBlockNotifier;

typedef struct VRMRCS VRMRCS; //352




typedef struct GSList GSList;
typedef struct GHashTable GHashTable;


typedef struct NamedClockList NamedClockList;

typedef struct NamedGPIOList NamedGPIOList;





enum {
    VIRTQUEUE_READ_DESC_ERROR = -1,
    VIRTQUEUE_READ_DESC_DONE = 0,   /* end of chain */
    VIRTQUEUE_READ_DESC_MORE = 1,   /* more buffers in chain */
};

#define VRING_DESC_F_NEXT	1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE	2
#define VRING_DESC_F_INDIRECT	4
typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

#define QLIST_ENTRY(type)                                               \
struct {                                                                \
        struct type *le_next;   /* next element */                      \
        struct type **le_prev;  /* address of previous next element */  \
}
#define QLIST_HEAD(name, type)                                          \
struct name {                                                           \
        struct type *lh_first;  /* first element */                     \
}
#define QTAILQ_ENTRY(type)                                              \
union {                                                                 \
        struct type *tqe_next;        /* next element */                \
        QTailQLink tqe_circ;          /* link for circular backwards list */ \
}
#define QTAILQ_HEAD(name, type)                                         \
union name {                                                            \
        struct type *tqh_first;       /* first element */               \
        QTailQLink tqh_circ;          /* link for circular backwards list */ \
}

#define _(P)                                                                   \
	({                                                                     \
		typeof(P) val;                                                 \
		bpf_probe_read_kernel(&val, sizeof(val), &(P));                \
		val;                                                           \
	})
#define PHYS_MAP_NODE_NIL (((uint32_t)~0) >> 6)
#define U128_toU64 (((uint64_t)~0))
#define TARGET_PAGE_BITS 12
#define ADDR_SPACE_BITS 64    
#define PHYS_SECTION_UNASSIGNED 0
#define P_L2_BITS 9
#define P_L2_SIZE (1 << P_L2_BITS)
#define P_L2_LEVELS (((ADDR_SPACE_BITS - TARGET_PAGE_BITS - 1) / P_L2_BITS) + 1)

#define TARGET_PAGE_MASK   ((target_long)-1 << TARGET_PAGE_BITS)
#define SUBPAGE_IDX(addr) ((addr) & ~TARGET_PAGE_MASK)
typedef __SIZE_TYPE__ size_t;
typedef long unsigned int gpa_t;
typedef long unsigned int hwaddr;

typedef signed char __int8_t;
typedef unsigned char __uint8_t;
typedef signed short int __int16_t;
typedef unsigned short int __uint16_t;
typedef signed int __int32_t;
typedef unsigned int __uint32_t;
typedef signed long int __int64_t;
typedef unsigned long int __uint64_t;
typedef unsigned long int	uintptr_t;

typedef __uint8_t uint8_t;
typedef __uint16_t uint16_t;
typedef __uint32_t uint32_t;
typedef __uint64_t uint64_t;
typedef __int64_t int64_t;
typedef __int128_t Int128;
typedef int int32_t;
typedef int32_t target_long;
typedef uint32_t cell_t;
typedef uintptr_t ram_addr_t;
typedef uint64_t dma_addr_t;

struct kvm_io_bus;
struct io_ring_ctx;
struct kvm_io_device;

struct kvm_io_range {
	uint64_t addr;
	int len;
	struct kvm_io_device *dev;
};

struct kvm_io_bus {
	int dev_count;
	int ioeventfd_count;
	struct kvm_io_range range[];
};
struct  RCUCBFunc;
struct rcu_head {
    struct rcu_head *next;
    struct RCUCBFunc *func;
};

struct PhysPageEntry {
    /* How many bits skip to next level (in units of L2_SIZE). 0 for a leaf. */
    uint32_t skip : 6;
     /* index into phys_sections (!skip) or phys_map_nodes (skip) */
    uint32_t ptr : 26;
};

typedef PhysPageEntry Node[P_L2_SIZE];


struct Object
{
    /* private: */
    ObjectClass *class;
    ObjectFree *free;
    GHashTable *properties;
    uint32_t ref;
    Object *parent;
};




struct MemoryRegionSection {
    Int128 size;
    struct MemoryRegion *mr;
    flatview *fv;
    hwaddr offset_within_region;
    hwaddr offset_within_address_space;
    bool readonly;
    bool nonvolatile;
};




typedef struct PhysPageMap {
    struct rcu_head rcu;

    unsigned sections_nb;
    unsigned sections_nb_alloc;
    unsigned nodes_nb;
    unsigned nodes_nb_alloc;
    Node *nodes;
    MemoryRegionSection *sections;
} PhysPageMap;

typedef struct AddressSpaceDispatch {
    MemoryRegionSection *mru_section;
    /* This is a multi-level map on the physical address space.
     * The bottom level has pointers to MemoryRegionSections.
     */
    PhysPageEntry phys_map;
    PhysPageMap map;
}AddressSpaceDispatch;


struct VRingDesc
{
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
};


struct flatview {
    struct rcu_head rcu;
    unsigned ref;
    FlatRange *ranges;
    unsigned nr;
    unsigned nr_allocated;
    AddressSpaceDispatch *dispatch;
    MemoryRegion *root;
};

struct MemoryRegionCache {
    void *ptr;
    hwaddr xlat;
    hwaddr len;
    flatview *fv;
    struct MemoryRegionSection mrs;
    bool is_write;
};


struct VRMRCS {
    struct rcu_head rcu;
    struct MemoryRegionCache desc;
    struct MemoryRegionCache avail;
    struct MemoryRegionCache used;
};

typedef struct VRing
{
    unsigned int num;
    unsigned int num_default;
    unsigned int align;
    hwaddr desc;
    hwaddr avail;
    hwaddr used;
    struct VRMRCS *caches;
} VRing;

typedef struct VRingAvail
{
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
} VRingAvail;

typedef enum {
    DMA_DIRECTION_TO_DEVICE = 0,
    DMA_DIRECTION_FROM_DEVICE = 1,
} DMADirection;

typedef struct MemTxAttrs {
    /* Bus masters which don't specify any attributes will get this
     * (via the MEMTXATTRS_UNSPECIFIED constant), so that we can
     * distinguish "all attributes deliberately clear" from
     * "didn't specify" if necessary.
     */
    unsigned int unspecified:1;
    /* ARM/AMBA: TrustZone Secure access
     * x86: System Management Mode access
     */
    unsigned int secure:1;
    /* Memory access is usermode (unprivileged) */
    unsigned int user:1;
    /*
     * Bus interconnect and peripherals can access anything (memories,
     * devices) by default. By setting the 'memory' bit, bus transaction
     * are restricted to "normal" memories (per the AMBA documentation)
     * versus devices. Access to devices will be logged and rejected
     * (see MEMTX_ACCESS_ERROR).
     */
    unsigned int memory:1;
    /* Requester ID (for MSI for example) */
    unsigned int requester_id:16;
    /* Invert endianness for this page */
    unsigned int byte_swap:1;
    /*
     * The following are target-specific page-table bits.  These are not
     * related to actual memory transactions at all.  However, this structure
     * is part of the tlb_fill interface, cached in the cputlb structure,
     * and has unused bits.  These fields will be read by target-specific
     * helpers using env->iotlb[mmu_idx][tlb_index()].attrs.target_tlb_bitN.
     */
    unsigned int target_tlb_bit0 : 1;
    unsigned int target_tlb_bit1 : 1;
    unsigned int target_tlb_bit2 : 1;
} MemTxAttrs;

#define MEMTXATTRS_UNSPECIFIED ((MemTxAttrs) { .unspecified = 1 })

struct iovecc
  {
    uint64_t *iov_base;	/* Pointer to data.  */
    unsigned long iov_len;	/* Length of data.  */
  };


typedef struct ResettableState {
    unsigned count;
    bool hold_phase_pending;
    bool exit_phase_in_progress;
}ResettableState;

typedef struct DeviceState {
    /*< private >*/
    Object parent_obj;
    /*< public >*/

    char *id;
    char *canonical_path;
    bool realized;
    bool pending_deleted_event;
    int64_t pending_deleted_expires_ms;
    QDict *opts;
    int hotplugged;
    bool allow_unplug_during_migration;
    BusState *parent_bus;
    QLIST_HEAD(, NamedGPIOList) gpios;
    QLIST_HEAD(, NamedClockList) clocks;
    QLIST_HEAD(, BusState) child_bus;
    int num_child_bus;
    int instance_id_alias;
    int alias_required_for_version;
    ResettableState reset;
    GSList *unplug_blockers;
}DeviceState;

typedef struct VirtQueueElement
{
    unsigned int index;
    unsigned int len;
    unsigned int ndescs;
    unsigned int out_num;
    unsigned int in_num;
    hwaddr *in_addr;
    hwaddr *out_addr;
    struct iovec *in_sg;
    struct iovec *out_sg;
} VirtQueueElement;
struct VirtQueue;
struct VirtIOHandleOutput;
struct VirtIODevice;


struct MemoryListener {

    void (*begin)(MemoryListener *listener);
    void (*commit)(MemoryListener *listener);
    void (*region_add)(MemoryListener *listener, MemoryRegionSection *section);
    void (*region_del)(MemoryListener *listener, MemoryRegionSection *section);
    void (*region_nop)(MemoryListener *listener, MemoryRegionSection *section);
    void (*log_start)(MemoryListener *listener, MemoryRegionSection *section,
                      int old, int new);
    void (*log_stop)(MemoryListener *listener, MemoryRegionSection *section,
                     int old, int new);
    void (*log_sync)(MemoryListener *listener, MemoryRegionSection *section);
    void (*log_sync_global)(MemoryListener *listener);
    void (*log_clear)(MemoryListener *listener, MemoryRegionSection *section);
    void (*log_global_start)(MemoryListener *listener);
    void (*log_global_stop)(MemoryListener *listener);
    void (*log_global_after_sync)(MemoryListener *listener);
    void (*eventfd_add)(MemoryListener *listener, MemoryRegionSection *section,
                        bool match_data, uint64_t data, EventNotifier *e);
    void (*eventfd_del)(MemoryListener *listener, MemoryRegionSection *section,
                        bool match_data, uint64_t data, EventNotifier *e);
    void (*coalesced_io_add)(MemoryListener *listener, MemoryRegionSection *section,
                               hwaddr addr, hwaddr len);
    void (*coalesced_io_del)(MemoryListener *listener, MemoryRegionSection *section,
                               hwaddr addr, hwaddr len);

    unsigned priority;
    const char *name;
    AddressSpace *address_space;
    QTAILQ_ENTRY(MemoryListener) link;
    QTAILQ_ENTRY(MemoryListener) link_as;
};



struct AddressSpace {
    /* private: */
    struct rcu_head rcu;
    char *name;
    MemoryRegion *root;

    /* Accessed via RCU.  */
    flatview *current_map;

    int ioeventfd_nb;
    struct MemoryRegionIoeventfd *ioeventfds;
    QTAILQ_HEAD(, MemoryListener) listeners;
    QTAILQ_ENTRY(AddressSpace) address_spaces_link;
};




struct AddrRange {
    Int128 start;
    Int128 size;
};


struct FlatRange {
    MemoryRegion *mr;
    hwaddr offset_in_region;
    AddrRange addr;
    uint8_t dirty_log_mask;
    bool romd_mode;
    bool readonly;
    bool nonvolatile;
};



struct VirtIODevice
{
    DeviceState parent_obj;
    const char *name;
    uint8_t status;
    uint8_t isr;
    uint16_t queue_sel;
    uint64_t guest_features;
    uint64_t host_features;
    uint64_t backend_features;
    size_t config_len;
    void *config;
    uint16_t config_vector;
    uint32_t generation;
    int nvectors;
    struct VirtQueue *vq;
    MemoryListener listener;
    uint16_t device_id;
    /* @vm_running: current VM running state via virtio_vmstate_change() */
    bool vm_running;
    bool broken; /* device in invalid state, needs reset */
    bool use_disabled_flag; /* allow use of 'disable' flag when needed */
    bool disabled; /* device in temporarily disabled state */
    bool use_started;
    bool started;
    bool start_on_kick; /* when virtio 1.0 feature has not been negotiated */
    bool disable_legacy_check;
    bool vhost_started;
    VMChangeStateEntry *vmstate;
    char *bus_name;
    uint8_t device_endian;
    bool use_guest_notifier_mask;
    AddressSpace *dma_as;
    QLIST_HEAD(, VirtQueue) *vector_queues;
    QTAILQ_ENTRY(VirtIODevice) next;
};

typedef void (*VirtIOHandleOutput)(struct VirtIODevice *, struct VirtQueue *);
struct EventNotifier {
    int rfd;
    int wfd;
    bool initialized;
};

struct VirtQueue //152
{
    VRing vring;
    VirtQueueElement *used_elems;

    /* Next head to pop */
    uint16_t last_avail_idx;
    bool last_avail_wrap_counter;

    /* Last avail_idx read from VQ. */
    uint16_t shadow_avail_idx;
    bool shadow_avail_wrap_counter;

    uint16_t used_idx;
    bool used_wrap_counter;

    /* Last used index value we have signalled on */
    uint16_t signalled_used;

    /* Last used index value we have signalled on */
    bool signalled_used_valid;

    /* Notification enabled? */
    bool notification;

    uint16_t queue_index;

    unsigned int inuse;

    uint16_t vector;
    VirtIOHandleOutput handle_output;
    struct VirtIODevice *vdev;
    EventNotifier guest_notifier;
    EventNotifier host_notifier;
    bool host_notifier_enabled;
    QLIST_ENTRY(VirtQueue) node;
};
typedef int __bitwise __kernel_rwf_t;
struct io_uring_sqe_bpf {
	uint8_t	opcode;		/* type of operation for this sqe */
	uint8_t	flags;		/* IOSQE_ flags */
	uint16_t	ioprio;		/* ioprio for the request */
	int32_t	fd;		/* file descriptor to do IO on */
	union {
		uint64_t	off;	/* offset into file */
		uint64_t	addr2;
		struct {
			uint32_t	cmd_op;
			uint32_t	__pad1;
		};
	};
	union {
		uint64_t	addr;	/* pointer to buffer or iovecs */
		uint64_t	splice_off_in;
	};
	uint32_t	len;		/* buffer size or number of iovecs */
	union {
		__kernel_rwf_t	rw_flags;
		uint32_t		fsync_flags;
		uint16_t		poll_events;	/* compatibility */
		uint32_t		poll32_events;	/* word-reversed for BE */
		uint32_t		sync_range_flags;
		uint32_t		msg_flags;
		uint32_t		timeout_flags;
		uint32_t		accept_flags;
		uint32_t		cancel_flags;
		uint32_t		open_flags;
		uint32_t		statx_flags;
		uint32_t		fadvise_advice;
		uint32_t		splice_flags;
		uint32_t		rename_flags;
		uint32_t		unlink_flags;
		uint32_t		hardlink_flags;
		uint32_t		xattr_flags;
		uint32_t		msg_ring_flags;
		uint32_t		uring_cmd_flags;
	};
	uint64_t	user_data;	/* data to be passed back at completion time */
	/* pack this to avoid bogus arm OABI complaints */
	union {
		/* index into fixed buffers, if used */
		uint16_t	buf_index;
		/* for grouped buffer selection */
		uint16_t	buf_group;
	} __attribute__((packed));
	/* personality to use, if used */
	uint16_t	personality;
	union {
		int32_t	splice_fd_in;
		uint32_t	file_index;
		struct {
			uint16_t	addr_len;
			uint16_t	__pad3[1];
		};
	};
	union {
		struct {
			uint64_t	addr3;
			uint64_t	__pad2[1];
		};
		/*
		 * If the ring is initialized with IORING_SETUP_SQE128, then
		 * this field is used for 80 bytes of arbitrary command data
		 */
		uint8_t	cmd[0];
	};
};

typedef struct MemoryRegion {
    Object parent_obj;
    bool romd_mode;
    bool ram;
    bool subpage;
    bool readonly; /* For RAM regions */
    bool nonvolatile;
    bool rom_device;
    bool flush_coalesced_mmio;
    uint8_t dirty_log_mask;
    bool is_iommu;
    RAMBlock *ram_block;
    Object *owner;
    const MemoryRegionOps *ops;
    void *opaque;
    MemoryRegion *container;
    int mapped_via_alias; /* Mapped via an alias, container might be NULL */
    Int128 size;
    hwaddr addr;
    void (*destructor)(MemoryRegion *mr);
    uint64_t align;
    bool terminates;
    bool ram_device;
    bool enabled;
    bool warning_printed; /* For reservations */
    uint8_t vga_logging_count;
    MemoryRegion *alias;
    hwaddr alias_offset;
    int32_t priority;
    QTAILQ_HEAD(, MemoryRegion) subregions;
    QTAILQ_ENTRY(MemoryRegion) subregions_link;
    QTAILQ_HEAD(, CoalescedMemoryRange) coalesced;
    const char *name;
    unsigned ioeventfd_nb;
    MemoryRegionIoeventfd *ioeventfds;
    RamDiscardManager *rdm; /* Only for RAM */
}MemoryRegion ;

struct io_uring_bpf_ctx {
	uint32_t	vq_num;
    uint64_t	vq_addr;
    uint64_t	L1Cache;
	uint64_t	L2Cache;
    uint8_t qemu_router;
    int    begin;
};

typedef struct RAMBlock {
    struct rcu_head rcu;
    MemoryRegion *mr;
    uint8_t *host;
    uint8_t *colo_cache; /* For colo, VM's ram cache */
    ram_addr_t offset;
    ram_addr_t used_length;
    ram_addr_t max_length;
    void (*resized)(const char*, uint64_t length, void *host);
    uint32_t flags;
    /* Protected by iothread lock.  */
    char idstr[256];
    /* RCU-enabled, writes protected by the ramlist lock */
    QLIST_ENTRY(RAMBlock) next;
    QLIST_HEAD(, RAMBlockNotifier) ramblock_notifiers;
    int fd;
    size_t page_size;
    /* dirty bitmap used during migration */
    unsigned long *bmap;
    /* bitmap of already received pages in postcopy */
    unsigned long *receivedmap;

    unsigned long *clear_bmap;
    uint8_t clear_bmap_shift;
    ram_addr_t postcopy_length;
} RAMBlock;

typedef struct subpage_t {
    MemoryRegion iomem;
    flatview *fv;
    hwaddr base;
    uint16_t sub_section[];
} subpage_t;

typedef struct Qcow2CachedTable {
    int64_t  offset;
    uint64_t lru_counter;
    int      ref;
    bool     dirty;
} Qcow2CachedTable;
struct Qcow2Cache {
    Qcow2CachedTable       *entries;
    struct Qcow2Cache      *depends;
    int                     size;
    int                     table_size;
    bool                    depends_on_flush;
    void                   *table_array;
    uint64_t                lru_counter;
    uint64_t                cache_clean_lru_counter;
};
struct L2cache_find_ctx {
    uint64_t entries_addr;
    uint64_t offset;
    int i;
    int ret;
    int size;
    int lookup_index;
    int min_lru_index;
    uint64_t min_lru_counter;
};

typedef struct fast_map {
    struct iovecc iovec[256];
    uint32_t in_num;
    uint32_t out_num;
    uint32_t type;
    bool fast;
    uint32_t wfd;
    uint32_t fd;
    uint32_t id;
    uint64_t offset;
} Fast_map;

typedef struct VRingUsedElem
{
    uint32_t id;
    uint32_t len;
} VRingUsedElem;


typedef struct VRingUsed
{
    uint16_t flags;
    uint16_t idx;
    VRingUsedElem ring[];
} VRingUsed;

typedef struct Useraddr
{
    uint64_t used_idx;
    uint64_t last_avail_idx;
    uint64_t caches_used;
    uint64_t vring_used;
    uint64_t avail_idx;
    uint64_t vdev_isr;
    uint64_t shadow_avail_idx;
    uint64_t pa;
    uint32_t vring_num;
    uint32_t wfd;
    uint32_t subreq_num;
    uint32_t id;
    VRingUsedElem elem;
} Useraddr;

struct host_extent_status {
	uint32_t es_lblk;	/* first logical block extent covers */
	uint32_t es_len;	/* length of extent in block */
	uint64_t es_pblk;	/* first physical block */
};
struct virtio_blk_outhdr {
	// unsigned int 	ib_enable;
	// struct host_extent_status ib_es[15];
	// unsigned int 	ib_es_num;
	/* VIRTIO_BLK_T* */
	uint32_t type;
	/* io priority. */
	uint32_t ioprio;
	/* Sector (ie. 512 byte offset) */
	uint64_t sector;
};

struct phys_page_find_ctx {
	AddressSpaceDispatch *d;	
	Node *nodes;	
	PhysPageEntry *p;
    PhysPageEntry *lp;
    uint32_t *i;
    struct MemoryRegionSection *section;
    bool *ret;
    hwaddr *indexx;
};

struct vec_pop_ctx {
    Fast_map *result;
    uint32_t *vq_id;
    uint32_t *rc;
    uint32_t *in_num;
    uint32_t *out_num;
    uint16_t *head;
    struct VRingDesc *desc;
    AddressSpace *as;
    struct MemoryRegionCache *desc_cache;
};

struct req_pop_ctx {
    uint32_t req_num;
    uint32_t vq_id;
    uint64_t vq_addr;
    void *ctx;
    int error;
};

struct count_sc_ctx {
    uint64_t *l2_slice;
    unsigned *l2_index;
    int  nb_clusters;
    int  count;
    int error;
    int i;
};

struct count_s_w_c_ctx {
    uint64_t *l2_slice;
    int  l2_index;
    uint64_t  l2_entry;
    uint64_t  expected_offset;
    int  nb_clusters;
    int i;
};

struct qcow2_co_pwritev_ctx {
    int64_t offset;
    uint64_t host_offset;
    int64_t bytes;
    uint32_t curent_bytes;
    Fast_map *qiov;
    struct Useraddr *user;
    int64_t qiov_offset;
    uint64_t L1Cache;
    int64_t L2Cache;
    uint32_t iter;
    uint32_t need_alloc;
    struct io_uring_bpf_ctx *ctxx;
    void *map;
    void *user_map;
};

struct qcow2_co_preadv_ctx {
    int64_t offset;
    uint64_t host_offset;
    int64_t bytes;
    uint32_t curent_bytes;
    Fast_map *qiov;
    struct Useraddr *user;
    int64_t qiov_offset;
    uint64_t L1Cache;
    int64_t L2Cache;
    uint32_t iter;
    struct io_uring_bpf_ctx *ctxx;
    void *map;
    void *user_map;
};

#endif
