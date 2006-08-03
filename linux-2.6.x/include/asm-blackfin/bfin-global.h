/*
 * Global extern defines for blackfin
 *
 */

#ifndef _BFIN_GLOBAL_H_
#define _BFIN_GLOBAL_H_

#ifndef __ASSEMBLY__
#include <asm-generic/sections.h>
#include <asm/ptrace.h>
#include <asm/user.h>
#include <linux/linkage.h>

extern unsigned long get_cclk(void);
extern unsigned long get_sclk(void);
extern int init_arch_irq(void);
extern void bfin_reset(void);
extern void dump_bfin_regs(struct pt_regs *fp, void *);
extern void _cplb_hdr(void);
/* Blackfin cache functions */
extern void bfin_icache_init(void);
extern void bfin_dcache_init(void);
extern int read_iloc(void);
extern int bfin_console_init(void);
extern asmlinkage void lower_to_irq14(void);
extern void init_dma(void);
extern void program_IAR(void);
extern void evt14_softirq(void);
extern asmlinkage void asm_do_IRQ(unsigned int irq, struct pt_regs *regs);
extern void bfin_gpio_interrupt_setup(int irq, int irq_pfx, int type);

extern void free_initmem(void);
extern void l1sram_init(void);
extern void l1_data_A_sram_init(void);
extern void l1_inst_sram_init(void);

extern unsigned long l1sram_alloc(unsigned long);
extern unsigned long l1_data_A_sram_alloc(unsigned long);
extern unsigned long l1_data_B_sram_alloc(unsigned long);
extern unsigned long l1_inst_sram_alloc(unsigned long);
extern unsigned long l1_data_sram_zalloc(unsigned long);
extern int l1sram_free(unsigned long);
extern int l1_data_A_sram_free(unsigned long);
extern int l1_data_B_sram_free(unsigned long);
extern int l1_inst_sram_free(unsigned long);
extern int l1_data_sram_free(unsigned long);

extern char *bfin_board_name __attribute__ ((weak));
extern unsigned long wall_jiffies;
extern unsigned long memory_end;
extern unsigned long memory_mtd_end;
extern unsigned long memory_mtd_start;
extern unsigned long mtd_size;
extern unsigned long ipdt_table[];
extern unsigned long dpdt_table[];
extern unsigned long icplb_table[];
extern unsigned long dcplb_table[];

extern unsigned long ipdt_swapcount_table[];
extern unsigned long dpdt_swapcount_table[];

extern unsigned long table_start, table_end;

extern struct file_operations dpmc_fops;
extern char _start;
extern int _ramstart, _ramend, _rambase;
extern unsigned long memory_start, memory_end;
extern unsigned long memory_mtd_end;
extern char _stext_l1[], _etext_l1[], _sdata_l1[], _edata_l1[], _sbss_l1[],
    _ebss_l1[], _l1_lma_start[];
#endif

#endif				/* _BLACKFIN_H_ */
