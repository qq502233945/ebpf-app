/* SPDX-License-Identifier: MIT */

#include "syscall.h"
#include <liburing.h>

int io_uring_enter(unsigned int fd, unsigned int to_submit,
		   unsigned int min_complete, unsigned int flags, sigset_t *sig)
{
	return __sys_io_uring_enter(fd, to_submit, min_complete, flags, sig);
}

int io_uring_enter2(unsigned int fd, unsigned int to_submit,
		    unsigned int min_complete, unsigned int flags,
		    sigset_t *sig, size_t sz)
{
	return __sys_io_uring_enter2(fd, to_submit, min_complete, flags, sig,
				     sz);
}

int io_uring_setup(unsigned int entries, struct io_uring_params *p)
{
	return __sys_io_uring_setup(entries, p);
}

int io_uring_register(unsigned int fd, unsigned int opcode, const void *arg,
		      unsigned int nr_args)
{
	return __sys_io_uring_register(fd, opcode, arg, nr_args);
}

struct io_uring_sqe *io_uring_get_sqe_bpf(struct io_uring *ring)
{
	struct io_uring_sq *sq = &ring->sq;
	unsigned int head, next = sq->sqe_tail + 1;
	int shift = 0;

	if (ring->flags & IORING_SETUP_SQE128)
		shift = 1;
	if (!(ring->flags & IORING_SETUP_SQPOLL))
		head = *sq->khead;
	else
		head = *sq->khead;

	if (next - head <= sq->ring_entries) {
		struct io_uring_sqe *sqe;

		sqe = &sq->sqes[(sq->sqe_tail & sq->ring_mask) << shift];
		sq->sqe_tail = next;
		return sqe;
	}

	return NULL;
}