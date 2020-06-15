#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sched.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "sb_api.h"
#include "header.h"

static int smoke_bomb_fd = -1;
int _smoke_bomb_write_to_lkm(char *fname, char *buf, unsigned int len)
{
    int ret = 0;
    int size;

    if (!fname || !buf || !len)
    {
        printf("Input is NULL\n");
        return -1;
    }

	if (smoke_bomb_fd < 0) {
	    smoke_bomb_fd = open(fname, O_WRONLY, S_IXUSR | S_IROTH);
    	if (smoke_bomb_fd < 0)
    	{
        	printf("fail to open : %s\n", fname);
        	return -1;
    	}
	}

    size = write(smoke_bomb_fd, buf, len);
    if(size != len)
    {
        printf("fail to write : %s\n", fname);
        ret = -1;
    }
/*
    if(fd)
    {
        close(fd);
    }*/
    return ret;
}

int _smoke_bomb_cmd(unsigned int cmd, unsigned long dsva, unsigned long deva)
{
	int r;
	struct smoke_bomb_cmd sb_cmd = {
		.cmd = cmd,
		.arg = {
			.dsva = dsva,
			.deva = deva,
		},
	};

	r = _smoke_bomb_write_to_lkm(SMOKE_BOMB_PROC_FULL_NAME, (char*)&sb_cmd, sizeof(sb_cmd));
	if (r)
		return r;
	
	return sb_cmd.ret;
}

void _smoke_bomb_ensure_page_map(unsigned long sva, unsigned long size)
{
	/* [ToDo] support multiple pages */
	int r;
	unsigned int val;
	unsigned int *ptr = (unsigned int *)sva;
	
	asm volatile ("ldr %0, [%1]\n": "=r" (val): "r" (ptr));
	asm volatile ("isb\n");

#ifdef _SMOKE_BOMB_ARMV7
    asm volatile ("dmb\n");	
#else
	asm volatile ("dmb ish\n");	
#endif

/*
	r = mlock((void *)sva, size);
	if (r) {
		printf("mlock error : %d\n", errno);
		return;
	}*/
}

void _smoke_bomb_restore_page_map(unsigned long sva, unsigned long size)
{
	int r;

	r = munlock((void *)sva, size);
	if (r) {
		printf("munlock error : %d\n", errno);
	}
}


/* set FIFO scheduler to disable preemption, backup original attributes to parameters */
int _smoke_bomb_set_sched_fifo(int *sched_policy, int *sched_prio)
{
	struct sched_param param;
	struct sched_param new_param;
	int tmp_policy, tmp_prio;

	if (sched_getparam(0, &param) != 0) {
		printf("sched_getparam error : %d\n", errno);
		return -1;
	}
	tmp_policy = sched_getscheduler(0);
	tmp_prio = param.sched_priority;

	new_param.sched_priority = sched_get_priority_max(SCHED_FIFO);
	if (sched_setscheduler(0, SCHED_FIFO, &new_param) != 0) {
		printf("sched_setscheduler error : %d\n", errno);
		return -1;
	}

	*sched_policy = tmp_policy;
	*sched_prio = tmp_prio;
	return 0;
}
void _smoke_bomb_restore_sched(int sched_policy, int sched_prio)
{
	struct sched_param param;

	param.sched_priority = sched_prio;
	if (sched_setscheduler(0, sched_policy, &param) != 0) {
		printf("sched_setscheduler error : %d\n", errno);
		return;
	}
}

static int gsched_policy = -1, gsched_prio = -1;
static int is_manually_initialized = 0;
void smoke_bomb_init(unsigned int *addr, unsigned long size)
{
	if (is_manually_initialized == 1)
		return;
	//printf("smoke_bomb_init : %lx ~ %lx\n", (unsigned long)addr, (unsigned long)addr + size);
	_smoke_bomb_ensure_page_map(addr, size);
	_smoke_bomb_set_sched_fifo(&gsched_policy, &gsched_prio);
	_smoke_bomb_cmd(SMOKE_BOMB_CMD_INIT, addr, (unsigned long)addr + size);
}

void smoke_bomb_exit(unsigned int *addr, unsigned long size)
{
	int r;
	//printf("smoke_bomb_exit : %lx ~ %lx\n", (unsigned long)addr, (unsigned long)addr + size);

	if (is_manually_initialized == 1)
		return;

	//_smoke_bomb_restore_page_map(dsva, dsize);
	r = _smoke_bomb_cmd(SMOKE_BOMB_CMD_EXIT, addr, (unsigned long)addr + size);
	if (r)
		return;

	if (gsched_policy >= 0 && gsched_prio >= 0) {
		_smoke_bomb_restore_sched(gsched_policy, gsched_prio);
		gsched_policy = -1;
		gsched_prio = -1;
	}
}

void smoke_bomb_manually_init(unsigned int *addr, unsigned long size)
{
	_smoke_bomb_ensure_page_map(addr, size);
	_smoke_bomb_set_sched_fifo(&gsched_policy, &gsched_prio);
	_smoke_bomb_cmd(SMOKE_BOMB_CMD_INIT, addr, (unsigned long)addr + size);
	is_manually_initialized = 1;
}

void smoke_bomb_manually_exit(unsigned int *addr, unsigned long size)
{
	int r;
	//printf("smoke_bomb_exit : %lx ~ %lx\n", (unsigned long)addr, (unsigned long)addr + size);

	//_smoke_bomb_restore_page_map(dsva, dsize);
	r = _smoke_bomb_cmd(SMOKE_BOMB_CMD_EXIT, addr, (unsigned long)addr + size);
	if (r) {
		is_manually_initialized = 0;
		return;
	}

	if (gsched_policy >= 0 && gsched_prio >= 0) {
		_smoke_bomb_restore_sched(gsched_policy, gsched_prio);
		gsched_policy = -1;
		gsched_prio = -1;
	}
	is_manually_initialized = 0;
}

void smoke_bomb_dummy_init(void)
{
	asm volatile("nop");
	return;
}

void smoke_bomb_dummy_exit(void)
{
	asm volatile("nop");
	return;
}
