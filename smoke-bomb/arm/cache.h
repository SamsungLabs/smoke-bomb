#ifndef _SMOKE_BOMB_CACHE_H
#define _SMOKE_BOMB_CACHE_H

extern unsigned int l1_ways;
extern unsigned int l1_sets;
extern unsigned int l2_ways;
extern unsigned int l2_sets;

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

static inline void init_pmu(void)
{
    /* Enable user-mode access to counters. */
    asm volatile ("mcr p15, 0, %0, C9, C14, 0\n\t" :: "r" (1));

    /* Program PMU and enable all counters */
    asm volatile ("mcr p15, 0, %0, c9, c12, 0" :: "r"((1 | 16)));
    asm volatile ("mcr p15, 0, %0, c9, c12, 1" :: "r"(0x8000000f));
    asm volatile ("isb\n");
	asm volatile ("dsb\n");
}

static inline void select_event_l1d_init(void)
{
    init_pmu();
    
    asm volatile ("mcr p15, 0, %0, c9, c12, 5\n\t" :: "r" (0));
	asm volatile ("isb\n");
	asm volatile ("dsb\n");

	asm volatile ("mcr p15, 0, %0, c9, c13, 1\n\t" :: "r" (0x3));
	asm volatile ("isb\n");
	asm volatile ("dsb\n");
}

static inline unsigned int get_pmu_count(void)
{
    unsigned int count;

    asm volatile ("MRC p15, 0, %0, C9, C13, 2\t\n": "=r" (count));
    asm volatile ("isb\n");
	asm volatile ("dsb\n");
    return count;
}

static inline void flush_dcache(void *addr)
{
	unsigned long addr_long;

	addr_long = (unsigned long)addr;
	asm volatile ("MCR p15, 0, %0, c7, c14, 1\n" :: "r" (addr_long));
    asm volatile ("isb\n");
    asm volatile ("dsb\n");
}

static inline void flush_icache(void *addr)
{
	unsigned long addr_long;

	addr_long = (unsigned long)addr;
	asm volatile ("MCR p15, 0, %0, c7, c5, 1\n" :: "r" (addr_long));
    asm volatile ("isb\n");
    asm volatile ("dsb\n");
}

static inline void flush_dtlb(void *addr)
{
	unsigned long addr_long;

	addr_long = (unsigned long)addr;
	asm volatile ("MCR p15, 0, %0, c8, c6, 1\n" :: "r" (addr_long));
    asm volatile ("dsb\n");
    asm volatile ("isb\n");
}

static inline void flush_itlb(void *addr)
{
	unsigned long addr_long;

	addr_long = (unsigned long)addr;
	asm volatile ("MCR p15, 0, %0, c8, c5, 1\n" :: "r" (addr_long));
    asm volatile ("dsb\n");
    asm volatile ("isb\n");
}

static inline void flush_dtlb_all(void)
{
	unsigned long dummy = 0;
	
	asm volatile ("MCR p15, 0, %0, c8, c6, 0\n" :: "r" (dummy));
    asm volatile ("dsb\n");
    asm volatile ("isb\n");
}

static inline void flush_itlb_all(void)
{
	unsigned long dummy = 0;
	
	asm volatile ("MCR p15, 0, %0, c8, c5, 0\n" :: "r" (dummy));
    asm volatile ("dsb\n");
    asm volatile ("isb\n");
}

static inline unsigned int _get_sets(unsigned int level)
{
	
	unsigned int lev;
	unsigned int sidr;
	unsigned int sets;
	
	/* write CSSELR */
	lev = (level<<1) | (0);
	asm volatile ("MCR p15, 2, %0, c0, c0, 0\n" :: "r" (lev));
	asm volatile ("isb\n");
	asm volatile ("dsb\n"); 

	/* read CCSIDR */
	asm volatile ("MRC p15, 1, %0, c0, c0, 0\n\t": "=r" (sidr));
	asm volatile ("isb\n");
	asm volatile ("dsb\n");

	sets = ((sidr << 4) >> 17) + 1;
	return sets;
}

static inline unsigned int _get_ways(unsigned int level)
{
	
	unsigned int lev;
	unsigned int sidr;
	unsigned int ways;
	
	/* write CSSELR */
	lev = (level<<1) | (0);
	asm volatile ("MCR p15, 2, %0, c0, c0, 0\n" :: "r" (lev));
	asm volatile ("isb\n");
	asm volatile ("dsb\n"); 

	/* read CCSIDR */
	asm volatile ("MRC p15, 1, %0, c0, c0, 0\n\t": "=r" (sidr));
	asm volatile ("isb\n");
	asm volatile ("dsb\n");

	ways = ((sidr << 19) >> 22) + 1;
	return ways;
}


static inline unsigned int get_l1_ways(void)
{
	return _get_ways(0);
}

static inline unsigned int get_l1_sets(void)
{
	return _get_sets(0);
}

static inline unsigned int get_l2_ways(void)
{
	return _get_ways(1);
}

static inline unsigned int get_l2_sets(void)
{
	return _get_sets(1);
}

static inline unsigned int get_l2_way_size(void)
{
	return get_l2_sets() * 64;
}

static inline unsigned int _get_set_idx_from_addr(void *addr, int level)
{
	unsigned int idx_bits;
	unsigned int addr32;
	unsigned int sets;

	if (level == 0)
		sets = l1_sets;
	else
		sets = l2_sets;

	for (idx_bits = 1; idx_bits < 18; idx_bits++) {
		if (sets == (1 << idx_bits))
			break;
	}

	addr32 = (unsigned int)addr;
	return (addr32 << (32 - idx_bits - 6)) >> (32 - idx_bits);
}

static inline unsigned int get_l1_set_idx_from_addr(void *addr)
{
	return _get_set_idx_from_addr(addr, 0);
}

static inline unsigned int get_l2_set_idx_from_addr(void *addr)
{
	return _get_set_idx_from_addr(addr, 1);
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

static inline void flush_l1_dcache_set(unsigned int set, unsigned int ways)
{
    unsigned int way;
    
    for (way=0; way<ways; way++)
        flush_l1_dcache(set, way);
}

static inline void flush_l2_dcache(unsigned int set, unsigned int way)
{
	unsigned int val;

    /* Clean & Invalidate L2 */
    /* Operation == DCCISW */
    val = 0x00000001;   // L2
    val = (val | (set << 6));
    val = (val | (way << 28)); /* l2 - 16 way, 4bit, [31:28] */
    __asm__ __volatile__ ("MCR p15, 0, %0, c7, c14, 2\n" :: "r" (val));
    __asm__ __volatile__ ("isb\n");
    __asm__ __volatile__ ("dsb\n");
}

static inline void flush_l2_dcache_set(unsigned int set, unsigned int ways)
{
    unsigned int way;
    
    for (way=0; way<ways; way++)
        flush_l2_dcache(set, way);
}

static inline void flush_l2_dcache_all(unsigned int sets, unsigned int ways)
{
    unsigned int set, way;
    
    for (set=0; set<sets; set++)
        for (way=0; way<ways; way++)
            flush_l2_dcache(set, way);
}

#endif

