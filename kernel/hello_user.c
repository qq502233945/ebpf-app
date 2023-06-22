#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "trace_helpers.h"

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_link *link2 = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	struct bpf_program *ret_prog;
	struct bpf_map *map1,*map2;
	char filename[256];
	int err;
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
	ret_prog = bpf_object__find_program_by_name(obj, "bpf_get_idx_ret");
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	if (bpf_object__pin_maps(obj,"/sys/fs/bpf/")) {
		fprintf(stderr, "ERROR: pin map\n");
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
	link2 = bpf_program__attach(ret_prog);
	if (libbpf_get_error(link2)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link2 = NULL;
		goto cleanup;
	}

	read_trace_pipe();

 cleanup:
 	bpf_object__unpin_maps(obj,"/sys/fs/bpf/");
	bpf_link__destroy(link);
	bpf_link__destroy(link2);
	bpf_object__close(obj);
	return 0;
}
