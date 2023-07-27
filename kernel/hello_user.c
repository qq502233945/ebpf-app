#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
// #include <bpf/libbpf.h>
// #include <bpf/bpf.h>
#include "../libbpf/src/bpf.h"

#include "../libbpf/src/libbpf.h"
#include "../liburing/src/include/liburing.h"	
#include "trace_helpers.h"
#include "vmlinux.h"
#define DEBUGFS "/sys/kernel/debug/tracing/"

static volatile bool exiting = false;
struct iovec *vecs;
struct io_uring ring;
struct io_uring_sqe *sqe;
struct io_uring_cqe *cqe;
struct io_uring_params p;
int disk_fd = 0;
static void sig_handler(int sig)
{
	exiting = true;
}


static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const Fast_map *result = data;
	// struct io_uring_sqe *sqe;
	// struct io_uring_cqe *cqe;

	printf("%u\n", data_sz);

	return 0;
}
int io_uring_init()
{
	vecs = (struct iovec*)malloc(1024 * sizeof(struct iovec));
	p.flags = IORING_SETUP_SQPOLL; //using io-uring in polling mode
	int ret = io_uring_queue_init_params(512, &ring, &p);
	if (ret) {
		fprintf(stderr, "ring create failed: %d\n", ret);
		return 1;
	}
	if ((p.flags & IORING_SETUP_SQPOLL) && ret == -EPERM && geteuid()) {
		fprintf(stdout, "SQPOLL skipped for regular user\n");
		return 1;
	}
	disk_fd = open("/home/joer/p5800/rdisk.raw", __O_DIRECT|O_RDWR);
	if (disk_fd < 0) {
		if (errno == EINVAL)
			return 1;
		perror("file open");
		return 1;
	}


	ret = io_uring_register_files(&ring, &disk_fd, 1);
	if(ret < 0)
	{
		printf("io_uring_register_files fail , ret is:%d\n",ret);
		return 1;
	}
	return 0;
}
void io_uring_destroy()
{
	int	ret = io_uring_unregister_files(&ring);
	if (ret< 0) {
		printf("io_uring_unregister_files fail , ret is:%d\n",ret);
	}
	close(disk_fd);
	io_uring_queue_exit(&ring);
}
int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_link *link2 = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_program *ret_prog;
	struct bpf_map *map1,*map2,*ringmap;
	
	char filename[256];

	int err;
	int ring_fd=-1;

	struct ring_buffer *rb = NULL;

	// ring_fd = bpf_obj_get("/sys/fs/bpf/kernel_ringbuf");
	// if (ring_fd < 0) {
	// 	printf("create a global bpf ring buf\n");
	// 	ring_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "kernel_ringbuf", 0, 0, 4096*128, NULL);
	// 	if (ring_fd < 0) {
	// 		fprintf(stderr, "ERROR: bpf_map_create failed\n");
	// 		goto cleanup;
	// 	}
	// 	// ringmap = bpf_map_get(ring_fd);
	// 	// if (IS_ERR(ringmap))
	// 	// 	goto cleanup;

	// }
	
	printf("create a global bpf ring buf ok\n");
	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	prog = bpf_object__find_program_by_name(obj, "bpf_prog");
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}
	// ret_prog = bpf_object__find_program_by_name(obj, "bpf_get_idx_ret");
	// if (!prog) {
	// 	fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
	// 	goto cleanup;
	// }

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	ringmap = bpf_object__find_map_by_name(obj, "kernel_ringbuf");
	if (!ringmap) {
		printf("Failed to load array of maps from test prog\n");
		goto cleanup;
	}
	// err = bpf_map__reuse_fd(ringmap, ring_fd);
	// if (err) {
	// 	printf("Failed to set inner_map_fd for array of maps\n");
	// 	goto cleanup;
	// }
	// if (bpf_object__pin_maps(obj,"/sys/fs/bpf/")) {
	// 	fprintf(stderr, "ERROR: pin map\n");
	// 	goto cleanup;
	// }
	if(!bpf_map__is_pinned(ringmap))
	{
		// bpf_map__set_pin_path(ringmap,"/sys/fs/bpf/kernel_ringbuf");
		if(bpf_map__pin(ringmap,"/sys/fs/bpf/kernel_ringbuf"))
		{
			fprintf(stderr, "ERROR: pin map\n");
			goto cleanup;
		}
	}

	rb = ring_buffer__new(bpf_map__fd(ringmap), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	// map1 = bpf_object__find_map_by_name(obj, "IOVECS");
	// {
	// 	fprintf(stderr, "ERROR: find pin map\n");
	// 	goto cleanup;
	// }
		
	// map2 = bpf_object__find_map_by_name(obj, "ADDRS");
	// {
	// 	fprintf(stderr, "ERROR: find pin map\n");
	// 	goto cleanup;
	// }
	// err = bpf_map__pin(map1, "/sys/fs/bpf/");
	// {
	// 	fprintf(stderr, "ERROR: pin map\n");
	// 	goto cleanup;
	// }
	// err = bpf_map__pin(map2, "/sys/fs/bpf/");
	// {
	// 	fprintf(stderr, "ERROR: pin map\n");
	// 	goto cleanup;
	// }

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}
	// link2 = bpf_program__attach(ret_prog);
	// if (libbpf_get_error(link2)) {
	// 	fprintf(stderr, "ERROR: bpf_program__attach failed\n");
	// 	link2 = NULL;
	// 	goto cleanup;
	// }
	err = io_uring_init();
	if(err)
	{
		printf("Failed to create IO uring\n");
		goto cleanup;
	}


	signal(SIGINT, sig_handler);
	// int trace_fd;
	// trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	// if (trace_fd < 0)
	// 	goto cleanup;
	while (!exiting) {
		// static char buf[4096];
		// ssize_t sz;
		// sz = read(trace_fd, buf, sizeof(buf) - 1);
		// if (sz > 0) {
		// 	buf[sz] = 0;
		// 	puts(buf);
		// }
		
		ring_buffer__consume(rb);
}

 cleanup:
 	ring_buffer__free(rb);
 	bpf_map__unpin(ringmap,"/sys/fs/bpf/kernel_ringbuf");
	bpf_link__destroy(link);
	// bpf_link__destroy(link2);
	bpf_object__close(obj);
	io_uring_destroy();
	return 0;
}
