#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
// #include <bpf/libbpf.h>
// #include <bpf/bpf.h>
#include "../libbpf/src/bpf.h"
#include <stdlib.h>
#include "../libbpf/src/libbpf.h"
#include "../liburing/src/include/liburing.h"	
#include "trace_helpers.h"
#include "vmlinux.h"
#include <pthread.h> 
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#define DEBUGFS "/sys/kernel/debug/tracing/"

static volatile bool exiting = false;
struct iovec *vecs;
int wait_to_comp=0;
struct io_uring_sqe *sqe;
struct io_uring_cqe *cqe;
struct io_uring_params *p;
int disk_fd = 0;
void *buf;
size_t size = 1024*1024*2;
int shm_fd;
int trace_fd;
int trace_fd2;
int trace_fd3;
// struct io_uring *ring = (struct io_uring *)io_uring_addr;
struct io_uring *ring;
Fast_map *result;
int need_complete;

static void sig_handler(int sig)
{
	exiting = true;
}


static int handle_event(void *ctx, void *data, size_t data_sz)
{
	// result = data;

	memcpy(result, data, sizeof(Fast_map));  
	struct io_uring_sqe *sqe;
	unsigned int req_size = 680;
	int i=0;
	int j =0;
	int iov_num =0;
	int ret;
	// printf("data size  is %u\n",data_sz);
	for(i= 0; i<data_sz/req_size;i++ )
	{
		printf("result type  is %d, out is %d, in is %d\n",result[i].type,result[i].out_num,result[i].in_num);
		iov_num = result[i].out_num+result[i].in_num - 2;
		// for(j=0;j<iov_num;j++)
		// {
		// 	printf("offset is %lu\n",result[i].offset);
		// 	printf("iov base is 0x%lx, byte is %lu\n",(uint64_t)result[i].iovec[1+j].iov_base,
		// 		result[i].iovec[1+j].iov_len);
		// }
		sqe = io_uring_get_sqe(ring);
		if (!sqe) {
			printf("sqe fail \n");
			return 0;
		}
		// printf("submit!\n");
		switch (result[i].type)
		{
		case 0: // read
			io_uring_prep_readv(sqe, 0,  &result[i].iovec[1],iov_num, result[i].offset);
			sqe->flags |= IOSQE_FIXED_FILE;
			sqe->user_data = result->id;
			break;
		case 1: // write
			io_uring_prep_writev(sqe, 0, &result[i].iovec[1], iov_num,result[i].offset);
			sqe->flags |= IOSQE_FIXED_FILE;
			sqe->user_data = result->id;
			break;
		case 4: // flush
			io_uring_prep_fsync(sqe,0,IORING_FSYNC_DATASYNC);
			sqe->flags |= IOSQE_FIXED_FILE;
			sqe->user_data = result->id;
			break;
		// 	break;
		default:
			break;
		}

		sqe->user_data = 0;
		ret = __io_uring_flush_sq_bpf(ring);
		wait_to_comp += ret;
		ret = io_uring_submit(ring);
		if (ret != iov_num) {
			printf("submit got %d, wanted %d\n", ret, iov_num);
		}

	}
	
	// printf("*************\n");
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_link *link2 = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_program *ret_prog;
	struct bpf_map *map1,*map2,*ringmap,*usermap;
	u_int64_t addr1,addr2,addr3;

	char filename[256];
	int ret;
	int err;
	int ring_fd=-1;
	int user_map_fd, router_fd,ringbuffer_fd;
	struct ring_buffer *rb = NULL;
	FILE *fp = fopen("/home/joer/data.bin", "rb");

	ret = global_map_init(&user_map_fd,&router_fd);
	printf("user_map_fd is %d.\n",user_map_fd);
	printf("router_fd is %d.\n",router_fd);
	if(!ret)
		goto cleanup;

	fread(&addr1, sizeof(u_int64_t), 1, fp);
 	fread(&addr2, sizeof(u_int64_t), 1, fp);
    fread(&addr3, sizeof(u_int64_t), 1, fp);
	fclose(fp);
	trace_fd =  shmget((key_t)1234, size, 0666);
	if (trace_fd == -1)
    {
        printf("shmget error 1 \n");
    }
	buf = shmat(trace_fd, addr1, 0);
	if (buf == (void *)-1)
	{
		printf("shmat error 1\n");
	}
	trace_fd2 =  shmget((key_t)12345, sizeof(struct io_uring), 0666);
	if (trace_fd2 == -1)
    {
        printf("shmget error 2\n");
    }
	ring = shmat(trace_fd2, addr2, 0);
	if (buf == (void *)-1)
	{
		
		printf("shmat error 2\n");
	}
	trace_fd3 =  shmget((key_t)54321, sizeof(Fast_map), 0666);
	if (trace_fd3 == -1)
    {
        printf("shmget error 3\n");
    }
	result = shmat(trace_fd3, addr3, 0);
	if (buf == (void *)-1)
	{
		printf("shmat error 3\n");
	}

	printf("ret is %d.\n",ret);
	printf("kflags is %u.\n",*ring->sq.kflags);


	
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


	ringmap = bpf_object__find_map_by_name(obj, "kernel_ringbuf");
	if (!ringmap) {
		printf("Failed to load array of maps from test prog\n");
		goto cleanup;
	}
	map1 = bpf_object__find_map_by_name(obj, "Router");
	if (!map1) {
		printf("Failed to load array of maps from test prog\n");
		goto cleanup;
	}

	map2 = bpf_object__find_map_by_name(obj, "User_addr_map");
	if (!map1) {
		printf("Failed to load array of maps from test prog\n");
		goto cleanup;
	}
	ret = bpf_map__reuse_fd(map2,user_map_fd);
	close(user_map_fd);
	if(ret < 0)
	{
		printf("Failed to reuse_fd 1\n");
		goto cleanup;
	}
	ret = bpf_map__reuse_fd(map1,router_fd);
	close(router_fd);
	if(ret < 0)
	{
		printf("Failed to reuse_fd 2\n");
		goto cleanup;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}	

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

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

	int trace_fd3 = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd3 < 0)
		goto cleanup;
	printf("here is ok\n");
	struct io_uring_cqe *cqe;
	while (!exiting) {
		static char buf[4096];
		ssize_t sz;
		sz = read(trace_fd3, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}

		ring_buffer__consume(rb);
		// printf("process cqe\n");
		if(wait_to_comp>0)
		{
			need_complete = io_uring_wait_cqe_bpf(ring,&cqe);
			if(!need_complete)
			{
				// printf("cqe res = %d\n",cqe->res);
				io_uring_cqe_seen(ring, cqe);
				wait_to_comp--;
			}
		}
		signal(SIGINT, sig_handler);
}

 cleanup:
	
	munmap(buf, size);
	munmap(ring,sizeof(struct io_uring));
	close(trace_fd);
	close(trace_fd2);
 	ring_buffer__free(rb);
 	bpf_map__unpin(ringmap,"/sys/fs/bpf/kernel_ringbuf");
	// bpf_map__unpin(map1,"/sys/fs/bpf/Router");
	// bpf_map__unpin(map2,"/sys/fs/bpf/User_addr_map");
	bpf_link__destroy(link);
	// bpf_link__destroy(link2);
	bpf_object__close(obj);
	return 0;
}

int global_map_init(int *user_map_fd, int *router_fd)
{
	int ret,fd1,fd2;
	const char *user_file ="/sys/fs/bpf/User_addr_map";
	const char *user_router ="/sys/fs/bpf/Router";
	fd1 = bpf_obj_get(user_file);
	fd2 = bpf_obj_get(user_router);
	if(fd1<0)
	{
		printf("Failed to  user maps from BPFS, so create one\n");
		fd1 = bpf_map_create(BPF_MAP_TYPE_ARRAY, "User_addr_map",
					  sizeof(__u32), sizeof(Useraddr), 2048, NULL);
		if (fd1<0)
		{
			printf("usermap create error \n");
			return 0;
		}

		ret = bpf_obj_pin(fd1,user_file);
		if (ret<0)
		{
			printf("bpf_obj_pin error \n");
			return 0;
		}
	}

	if(fd2<0)
	{
		printf("Failed to  user maps from BPFS, so create one\n");
		fd2 = bpf_map_create(BPF_MAP_TYPE_ARRAY, "Router",
					  sizeof(__u32), sizeof(__u32), 8, NULL);
		if (fd2<0)
		{
			printf("usermap create error \n");
			return 0;
		}

		ret = bpf_obj_pin(fd2,user_router);
		if (ret<0)
		{
			printf("bpf_obj_pin error \n");
			return 0;
		}
	}
	*user_map_fd = fd1;
	*router_fd = fd2;
	return 1;
}
