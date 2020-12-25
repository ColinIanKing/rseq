/*
 * Copyright (C) 2020 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */

#define _GNU_SOURCE
#include <linux/rseq.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/syscall.h>
#include <string.h>
#include <setjmp.h>

static volatile struct rseq ___rseq;
static volatile uint64_t failed;
static volatile uint64_t segv;
static sigjmp_buf jmp_env;

#define OPTIMIZE0       __attribute__((optimize("-O0")))

#define set_rseq_ptr(value) *(uint64_t *)(&___rseq.rseq_cs) = (uint64_t)(uintptr_t)value;

static int sys_rseq(volatile struct rseq *rseq_abi, uint32_t rseq_len,
			int flags, uint32_t sig)
{
	return syscall(__NR_rseq, rseq_abi, rseq_len, flags, sig);
}


static void register_thread(uint32_t signature)
{
	int rc;

	memset((void *)&___rseq, 0, sizeof(___rseq));
	rc = sys_rseq(&___rseq, sizeof(___rseq), 0, signature);
	if (rc) {
		fprintf(stderr, "Failed to register rseq\n");
		exit(1);
	}
}

static void unregister_thread(uint32_t signature)
{
	int rc;
	rc = sys_rseq(&___rseq, sizeof(___rseq), RSEQ_FLAG_UNREGISTER, signature);
	set_rseq_ptr(NULL);
	if (rc) {
		fprintf(stderr, "Failed to register rseq\n");
		exit(1);
	}
}

#define NOPS()			\
	asm volatile(		\
		"nop\n"		\
		"nop\n"		\
		"nop\n"		\
		"nop\n"		\
	);


#define RSEQ_ACCESS_ONCE(x)     (*(__volatile__  __typeof__(x) *)&(x))

static int OPTIMIZE0 rseq_test(int cpu, uint32_t *signature)
{
	struct rseq_cs __attribute__((aligned(32))) ___cs = {
		0,
		0,
		(uintptr_t)(void *)&&l1,
		((uintptr_t)&&l2 - (uintptr_t)&&l1),
		(uintptr_t)&&l4
	};

	if (signature) {
		uint32_t *ptr = &&l4;
		ptr--;
		*signature = *ptr;
		return 0;
	}

l1:
	set_rseq_ptr(&___cs);
	if (cpu != ___rseq.cpu_id)
		goto l4;
	set_rseq_ptr(NULL);
	return 0;
l2:
	set_rseq_ptr(NULL);
	NOPS();
l4:
	set_rseq_ptr(NULL);
	return 1;
}

void sigsegv_handler(int sig)
{
	(void)sig;

	printf("SIGSEGV\n");
	segv++;
	siglongjmp(jmp_env, 1);
}

int main(int argc, char **argv)
{
	int cpu, ret, i;
	uint32_t signature = 0xdeadcaff;
	struct sigaction sa;

	failed = 0;
	segv = 0;

	(void)memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigsegv_handler;
	if (sigaction(SIGSEGV, &sa, NULL) < 0) {
		fprintf(stderr, "Failed to set SIGSEGV hhandler\n");
		exit(1);
	}

	rseq_test(-1, &signature);

	printf("SIG: %8.8" PRIx32 "\n", signature);

	while (!segv) {
		ret = sigsetjmp(jmp_env, 1);
		if (ret)
			break;

		register_thread(signature);
		for (failed = 0, i = 0; i < 100000; i++) {
			cpu = RSEQ_ACCESS_ONCE(___rseq.cpu_id_start);
			ret = rseq_test(cpu, NULL);
			if (ret) {
				failed++;
			}
		}
		unregister_thread(signature);

		if (failed | segv) {
			printf("%" PRIu64 " of %d failed, including %" PRIu64 " SIGSEGVs\n", failed, i, segv);
			failed = 0;
		}
	}

	return 0;
}
