#include <linux/sched.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>

#include "../header.h"

#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"

#define ARM32_SHORT_DESC_FIRST_VA_OFFSET (0x000FFFFF)
#define ARM32_SHORT_DESC_SECOND_VA_OFFSET (0x00000FFF)

#define ARM32_SHORT_DESC_FIRST_PHYS_MASK (0x00000000FFF00000)
#define ARM32_SHORT_DESC_SECOND_PHYS_MASK (0x00000000FFFFF000)

#define ARM32_LONG_DESC_FIRST_VA_OFFSET (0x3FFFFFFF)
#define ARM32_LONG_DESC_SECOND_VA_OFFSET (0x001FFFFF)
#define ARM32_LONG_DESC_THIRD_VA_OFFSET (0x00000FFF)

#define ARM32_LONG_DESC_FIRST_PHYS_MASK (0x000000FFC0000000)
#define ARM32_LONG_DESC_SECOND_PHYS_MASK (0x000000FFFFE00000)
#define ARM32_LONG_DESC_THIRD_PHYS_MASK (0x000000FFFFFFF000)

#ifndef __aarch64__

#if CONFIG_PGTABLE_LEVELS == 3

// 32bit long descriptor
static unsigned long levelVaOffset[4] = {ARM32_LONG_DESC_FIRST_VA_OFFSET, ARM32_LONG_DESC_FIRST_VA_OFFSET, ARM32_LONG_DESC_SECOND_VA_OFFSET, ARM32_LONG_DESC_THIRD_VA_OFFSET};
static phys_addr levelPhysMask[4] = {ARM32_LONG_DESC_FIRST_PHYS_MASK, ARM32_LONG_DESC_FIRST_PHYS_MASK, ARM32_LONG_DESC_SECOND_PHYS_MASK, ARM32_LONG_DESC_THIRD_PHYS_MASK};

#elif CONFIG_PGTABLE_LEVELS == 2

// 32bit short descriptor
static unsigned long levelVaOffset[4] = {ARM32_SHORT_DESC_FIRST_VA_OFFSET, ARM32_SHORT_DESC_FIRST_VA_OFFSET, ARM32_SHORT_DESC_FIRST_VA_OFFSET, ARM32_SHORT_DESC_SECOND_VA_OFFSET};
static phys_addr levelPhysMask[4] = {ARM32_SHORT_DESC_FIRST_PHYS_MASK, ARM32_SHORT_DESC_FIRST_PHYS_MASK, ARM32_SHORT_DESC_FIRST_PHYS_MASK, ARM32_SHORT_DESC_SECOND_PHYS_MASK};

#endif

static phys_addr _sb_get_pa(unsigned long va, unsigned int level, phys_addr pa)
{
    phys_addr retPA;

    retPA = ( (pa & levelPhysMask[level]) | (va & levelVaOffset[level]) );
    return retPA;
}

int sb_convert_va_to_pa(unsigned long va, phys_addr *pa)
{
    pgd_t *pgd;
    pmd_t *pmd;
    pte_t *pte;
    pud_t *pud;
    struct mm_struct *mm;
    phys_addr pa64;

    mm = current->active_mm;
    if(!mm)
    {
        sb_pr_err("get mm_struct error\n");
        return -1;
    }

    pgd = pgd_offset(mm, va);
    if ( pgd_none(*pgd) || pgd_bad(*pgd) )
    {
        // end at zero level.
        pa64 = _sb_get_pa(va, 0, pgd_val(*pgd));
        *pa = pa64;
        return 0;
    }

    pud = pud_offset(pgd, va);
    if ( pud_none(*pud) || pud_bad(*pud) )
    {
        // end at first level.
        pa64 = _sb_get_pa(va, 1, pud_val(*pud));
        *pa = pa64;
        return 0;
    }

	pmd = pmd_offset(pud, va);
	if ( pmd_none(*pmd) || pmd_bad(*pmd) )
	{
		// end at second level.
		pa64 = _sb_get_pa(va, 2, pmd_val(*pmd));
		*pa = pa64;
		return 0;
	}

	pte = pte_offset_map(pmd, va);
	if (!pte_present(*pte))
	{
		pte_unmap(pte);
		// error case
		return -1;
	}

	// end at third level.
	pa64 = _sb_get_pa(va, 3, pte_val(*pte));
	*pa = pa64;
	pte_unmap(pte);

	return 0;
}

#else /* __aarch64__ */

int sb_convert_va_to_pa(unsigned long va, phys_addr *pa)
{
	unsigned long ret = 0;
	unsigned long va_offset = 0;
	
	asm volatile ("AT S1E0R, %0\n" :: "r" (va));
	asm volatile ("isb\n");
	asm volatile ("MRS %0, PAR_EL1\n" : "=r" (ret));
	asm volatile ("isb\n");
	asm volatile ("dsb sy\n");

	/* check result */
	if ( ((ret << 63) >> 63) == 1 ) {
		sb_pr_err("address converting fail");
		return -1;
	}

	ret &= 0x0000FFFFFFFFF000UL;	/* extract PA */
	va_offset = va & 0x0000000000000FFFUL;
	ret |= va_offset;	/* apply va offset */
	*pa = ret;
	
	return 0;
}

#endif /* __aarch64__ */

/* preload function that is independent on arch */

void sb_preload(void)
{
	unsigned long va;
	phys_addr pa;
	unsigned int set1, set2;
	long pid;
	
	pid = get_pid_idx(current->pid);
	if (sdata_region[pid].preload_flag == 0) {
	
		sb_convert_va_to_pa(sdata_region[pid].sva, &pa);
        set1 = get_l1_set_idx_from_addr((void *)pa);
        set2 = get_l2_set_idx_from_addr((void *)pa);
        
        for (va = sdata_region[pid].sva; va < sdata_region[pid].eva; va += CACHE_LINE_SIZE) {
            flush_l1_dcache(set1, l1_ways - 1);
            flush_l2_dcache(set2, l2_ways - 1);
            pld_data((void *)va);
            flush_l2_dcache(set2, l2_ways - 1);

            set1++;
            set2++;
        }
        
        sdata_region[pid].preload_flag = 1;
        select_event_l1d_init();
    }
}

