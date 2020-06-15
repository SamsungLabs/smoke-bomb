#ifndef _SMOKE_BOMB_CACHE_H
#define _SMOKE_BOMB_CACHE_H

/* PMU related */
#define ARMV8_PMCR_E            (1 << 0) /* Enable all counters */
#define ARMV8_PMCR_P            (1 << 1) /* Reset all counters */
#define ARMV8_PMCR_C            (1 << 2) /* Cycle counter reset */
#define ARMV8_PMCNTENSET_EL0_EN (1 << 31) /* Performance Monitors Count Enable Set register */

#define ARMV8_PMUUSERNR_EN		(1 << 0)

extern unsigned int l1_ways;
extern unsigned int l1_sets;
extern unsigned int l2_ways;
extern unsigned int l2_sets;

static inline void init_pmu(void)
{
    uint32_t value = 0;
    asm volatile("MRS %0, PMCR_EL0" : "=r" (value));
    value |= ARMV8_PMCR_E;
    value |= ARMV8_PMCR_C;
    value |= ARMV8_PMCR_P;
    asm volatile("MSR PMCR_EL0, %0" : : "r" (value));
    asm volatile("MRS %0, PMCNTENSET_EL0" : "=r" (value));
    value |= ARMV8_PMCNTENSET_EL0_EN;
    asm volatile("MSR PMCNTENSET_EL0, %0" : : "r" (value));

    /* user enable */
    asm volatile("MRS %0, PMUSERENR_EL0" : "=r" (value));
    value |= ARMV8_PMUUSERNR_EN;
    asm volatile("MSR PMUSERENR_EL0, %0" :: "r" (value));
}

static inline void select_event_l1d_init(void)
{
    uint32_t value = 0;
    asm volatile("MRS %0, PMCR_EL0" : "=r" (value));
    value |= ARMV8_PMCR_E;
    value |= ARMV8_PMCR_C;
    value |= ARMV8_PMCR_P;
    asm volatile("MSR PMCR_EL0, %0" : : "r" (value));
    value = 1 << 0;
    asm volatile("MSR PMCNTENSET_EL0, %0" : : "r" (value));
    value = 0 & 0x1F;
    asm volatile("MSR PMSELR_EL0, %0" : : "r" (value));
    value = 0x03; /* value = L1D_CACHE_REFILL; */
    //value = L1D_CACHE_WB;
    //value = L2D_CACHE_REFILL;
    //value = L2D_CACHE_WB;
    asm volatile("MSR PMXEVTYPER_EL0, %0" : : "r" (value));
}

static inline unsigned int get_pmu_count(void)
{
    unsigned int ret;
    unsigned int counter = 0 & 0x1F;
    asm volatile("MSR PMSELR_EL0, %0" : : "r" (counter));
    asm volatile("ISB");
    asm volatile("MRS %0, PMXEVCNTR_EL0" : "=r"(ret));
    return ret;
}

static inline void flush_dcache(void *addr)
{
	asm volatile ("DC CIVAC, %0" :: "r"(addr));
    asm volatile ("DSB ISH");
    asm volatile ("ISB");
}

static inline void pld_data(void *addr)
{
	asm volatile ("PRFM PLDL1KEEP, [%x0]" :: "p" (addr));
	asm volatile ("DSB ISH");
    asm volatile ("ISB");
}

static inline void pld_data_l2(void *addr)
{
	asm volatile ("PRFM PLDL2KEEP, [%x0]" :: "p" (addr));
	asm volatile ("DSB ISH");
    asm volatile ("ISB");
}

static inline void ldr_data(void *addr)
{
	volatile unsigned int val;
	volatile unsigned long addr_int = (volatile unsigned long)addr;
	
	asm volatile ("ldr %0, [%1]\n": "=r" (val): "r" (addr_int));
	asm volatile ("ISB\n");
	asm volatile ("DMB ISH\n");
}

static inline unsigned int _get_sets(unsigned int level)
{
	unsigned int lev;
	unsigned int sidr;
	unsigned int sets;
	
	/* write CSSELR */
	lev = (level<<1) | (0);
	asm volatile ("MSR CSSELR_EL1, %0\n" :: "r" (lev));
	asm volatile ("ISB\n");
    asm volatile ("DSB SY\n");

	/* read CCSIDR */
	asm volatile ("MRS %0, CCSIDR_EL1\n\t": "=r" (sidr));
	asm volatile ("ISB\n");
    asm volatile ("DSB SY\n");

	sets = ((sidr << 4) >> 17) + 1;
	return sets;
}

static inline unsigned int _get_ways(unsigned int level)
{
	unsigned int lev = 0;
	unsigned int sidr;
	unsigned int ways;
	
	/* write CSSELR */
	lev = (level<<1) | (0);
	asm volatile ("MSR CSSELR_EL1, %0\n" :: "r" (lev));
	asm volatile ("ISB\n");
    asm volatile ("DSB SY\n");

	/* read CCSIDR */
	asm volatile ("MRS %0, CCSIDR_EL1\n\t": "=r" (sidr));
	asm volatile ("ISB\n");
    asm volatile ("DSB SY\n");

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
	unsigned long idx_bits;
	unsigned long addr64;
	unsigned int sets;

	if (level == 0)
		sets = l1_sets;
	else
		sets = l2_sets;

	for (idx_bits = 1; idx_bits < 18; idx_bits++) {
		if (sets == (1 << idx_bits))
			break;
	}

	addr64 = (unsigned long)addr;
	return (unsigned int)( (addr64 << (64 - idx_bits - 6)) >> (64 - idx_bits) );
}

static inline unsigned int get_l1_set_idx_from_addr(void *addr)
{
	return _get_set_idx_from_addr(addr, 0);
}

static inline unsigned int get_l2_set_idx_from_addr(void *addr)
{
	return _get_set_idx_from_addr(addr, 1);
}

static inline void flush_l1_dcache(unsigned int set, unsigned int way)
{
	volatile uint64_t value;
	
	value = 0x0000000000000000;
	value = (value | (set << 6));
	value = (value | (way << 30));
	asm volatile("DC CISW, %0\n"
		:
		: "r" (value)
		);
	asm volatile("ISB\n");
	asm volatile("DSB SY\n");
}

static inline void flush_l1_dcache_set(unsigned int set, unsigned int ways)
{
    unsigned int way;
    
    for (way=0; way<ways; way++)
        flush_l1_dcache(set, way);
}

static inline void flush_l2_dcache(unsigned int set, unsigned int way)
{
    volatile uint64_t value;
    
    value = 0x0000000000000000;
    value = (value | (1 << 1));
    value = (value | (set << 6));
    value = (value | (way << 28));
    
    asm volatile("DC CISW, %0\n"
        :
        : "r" (value)
        );
    asm volatile("ISB\n");
    asm volatile("DSB SY\n");
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

