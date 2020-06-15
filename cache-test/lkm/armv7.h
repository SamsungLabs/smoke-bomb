#ifndef _CACHE_TEST_ARMV7_H
#define _CACHE_TEST_ARMV7_H

static inline void init_pmu(void)
{
	/* Enable user-mode access to counters. */
    asm volatile ("mcr p15, 0, %0, C9, C14, 0\n\t" :: "r" (1));

	/* Program PMU and enable all counters */
	asm volatile ("mcr p15, 0, %0, c9, c12, 0" :: "r"((1 | 16)));
    asm volatile ("mcr p15, 0, %0, c9, c12, 1" :: "r"(0x8000000f));
}

static inline unsigned int lru_get_cycles(void)
{
	unsigned int cycles;

	asm volatile ("isb\n");
	asm volatile ("dmb\n");
	asm volatile ("MRC p15, 0, %0, C9, C13, 0\t\n": "=r" (cycles));
	asm volatile ("isb\n");

    return cycles;
}

static inline void select_pmu_event(unsigned int val)
{
	asm volatile ("mcr p15, 0, %0, c9, c13, 1\n\t" :: "r" (val));
	asm volatile ("isb\n");
	asm volatile ("dsb\n");
}

static inline void select_l2_line_fill(void)
{
	asm volatile ("mcr p15, 0, %0, c9, c12, 5\n\t" :: "r" (0));
	asm volatile ("isb\n");
	asm volatile ("dsb\n");
	
	select_pmu_event(0x17);
}

static inline void select_l2_access(void)
{
	asm volatile ("mcr p15, 0, %0, c9, c12, 5\n\t" :: "r" (0));
	asm volatile ("isb\n");
	asm volatile ("dsb\n");
	
	select_pmu_event(0x16);
}

static inline unsigned int get_pmu_count(void)
{
	unsigned int count;

	asm volatile ("MRC p15, 0, %0, C9, C13, 2\t\n": "=r" (count));
	asm volatile ("isb\n");
	asm volatile ("dsb\n");
    return count;
}

static inline void flush_l2_dcache(int set, int way)
{
	unsigned int val;

    /* Clean & Invalidate L2 */
    /* Operation == DCCISW */
    val = 0x00000001;   // L1
    val = (val | (set << 6));
    val = (val | (way << 28)); /* l2 - 16 way, 4bit, [31:28] */
    __asm__ __volatile__ ("MCR p15, 0, %0, c7, c14, 2\n" :: "r" (val));
    __asm__ __volatile__ ("isb\n");
    __asm__ __volatile__ ("dsb\n");
}

static inline void flush_l2_dcache_all(unsigned int set_num, unsigned int way_num)
{
	int set, way;
	for (set=0; set<set_num; set++)
		for (way=0; way<way_num; way++)
			flush_l2_dcache(set, way);
}

static inline void flush_l2_dcache_set(int set, unsigned int way_num)
{
	int way;
	for (way=0; way<way_num; way++)
		flush_l2_dcache(set, way);
}

static inline void flush_l1_dcache(int set, int way)
{
	unsigned int val;

    /* Clean & Invalidate L1 */
    /* Operation == DCCISW */
    val = 0x00000000;   // L1
    val = (val | (set << 6));   // set
    val = (val | (way << 30)); // way
    __asm__ __volatile__ ("MCR p15, 0, %0, c7, c14, 2\n" :: "r" (val));
    __asm__ __volatile__ ("isb\n");
    __asm__ __volatile__ ("dsb\n");
}

static inline void flush_l1_dcache_all(unsigned int set_num, unsigned int way_num)
{
	int set, way;
	for (set=0; set<set_num; set++)
		for (way=0; way<way_num; way++)
			flush_l1_dcache(set, way);
}

static inline void flush_l1_dcache_set(int set, unsigned int way_num)
{
	int way;
	for (way=0; way<way_num; way++)
		flush_l1_dcache(set, way);
}

static inline void flush_dcache(void *addr)
{
	unsigned int addr32;

	addr32 = (unsigned int)addr;
	__asm__ __volatile__ ("MCR p15, 0, %0, c7, c14, 1\n" :: "r" (addr32));
    __asm__ __volatile__ ("isb\n");
    __asm__ __volatile__ ("dsb\n");
}

static inline void flush_icache(void *addr)
{
	unsigned long addr_long;

	addr_long = (unsigned long)addr;
	asm volatile ("MCR p15, 0, %0, c7, c5, 1\n" :: "r" (addr_long));
    asm volatile ("isb\n");
    asm volatile ("dsb\n");
}

static inline unsigned int get_l2_set_num(void)
{
	unsigned int l2_level;
	unsigned int sidr;
	unsigned int l2_set_num;
	
	/* write CSSELR to L2 */
	l2_level = (1<<1) | (0);
	asm volatile ("MCR p15, 2, %0, c0, c0, 0\n" :: "r" (l2_level));
	asm volatile ("isb\n");
	asm volatile ("dsb\n"); 

	/* read CCSIDR */
	asm volatile ("MRC p15, 1, %0, c0, c0, 0\n\t": "=r" (sidr));
	asm volatile ("isb\n");
	asm volatile ("dsb\n");

	l2_set_num = ((sidr << 4) >> 17) + 1;
	return l2_set_num;
}

static inline void pld_data(void *addr)
{
	asm volatile ("PLD [%0]\n" :: "r" (addr));
	asm volatile ("isb\n");
	asm volatile ("dsb\n");
}

static inline void ldr_data(void *addr)
{
	unsigned int val;
	
	asm volatile ("ldr %0, [%1]\n": "=r" (val): "r" (addr));
	asm volatile ("isb\n");
	asm volatile ("dmb\n");
}

#endif
