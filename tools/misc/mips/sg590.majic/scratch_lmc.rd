REG = $scratch_LMC0_COMP_CTL 8
REG_FIELD = $scratch_LMC0_COMP_CTL nctl_csr 31 28, nctl_dat 19 16, pctl_csr 15 12, pctl_dat 4 0

REG = $scratch_LMC0_CTL 8
REG_FIELD = $scratch_LMC0_CTL ddr__nctl 31 28, ddr__pctl 27 24, slow_scf 23 23, xor_bank 22 22, max_write_batch 21 18, pll_bypass 16 16, rdimm_ena 15 15, r2r_slot 14 14, inorder_mwf 13 13, inorder_mrf 12 12, dreset 11 11, mode32b 10 10, fprch2 9 9, bprch 8 8, sil_lat 7 6, tskw 5 4, qs_dic 3 2, dic 1 0

REG = $scratch_LMC0_CTL1 8
REG_FIELD = $scratch_LMC0_CTL1 sil_mode 9 9, dcc_enable 8 8, data_layout 1 0

REG = $scratch_LMC0_DDR2_CTL 8
REG_FIELD = $scratch_LMC0_DDR2_CTL bank8 31 31, burst8 30 30, addlat 29 27, pocas 26 26, bwcnt 25 25, twr 24 22, silo_hc 21 21, ddr_eof 20 17, tfaw 16 12, crip_mode 11 11, ddr2t 10 10, odt_ena 9 9, qdll_ena 8 8, dll90_vlu 7 3, dll90_byp 2 2, rdqs 1 1, ddr2 0 0

REG = $scratch_LMC0_DELAY_CFG 8
REG_FIELD = $scratch_LMC0_DELAY_CFG dq 13 10, cmd 8 5, clk 3 0

REG = $scratch_LMC0_DUAL_MEMCFG 8
REG_FIELD = $scratch_LMC0_DUAL_MEMCFG bank8 19 19, row_lsb 18 16, cs_mask 7 0

REG = $scratch_LMC0_MEM_CFG0 8
REG_FIELD = $scratch_LMC0_MEM_CFG0 reset 31 31, silo_qc 30 30, bunk_ena 29 29, ded_err 28 25, sec_err 24 21, intr_ded_ena 20 20, intr_sec_ena 19 19, tcl 18 15, ref_int 14 9, pbank_lsb 8 5, row_lsb 4 2, ecc_ena 1 1, init_start 0 0

REG = $scratch_LMC0_MEM_CFG1 8
REG_FIELD = $scratch_LMC0_MEM_CFG1 comp_bypass 31 31, trrd 30 28, caslat 27 25, tmrd 24 22, trfc 21 17, trp 16 13, twtr 12 9, trcd 8 5, tras 4 0

REG = $scratch_LMC0_PLL_CTL 8
REG_FIELD = $scratch_LMC0_PLL_CTL fasten_n 28 28, div_reset 27 27, reset_n 26 26, clkf 25 14, clkr 13 8, en16 5 5, en12 4 4, en8 3 3, en6 2 2, en4 1 1, en2 0 0

REG = $scratch_LMC0_PLL_STATUS 8
REG_FIELD = $scratch_LMC0_PLL_STATUS ddr__nctl 31 27, ddr__pctl 26 22, rfslip 1 1, fbslip 0 0

REG = $scratch_LMC0_RODT_COMP_CTL 8
REG_FIELD = $scratch_LMC0_RODT_COMP_CTL enable 16 16, nctl 11 8, pctl 4 0

REG = $scratch_LMC0_RODT_CTL 8
REG_FIELD = $scratch_LMC0_RODT_CTL rodt_hi3 31 28, rodt_hi2 27 24, rodt_hi1 23 20, rodt_hi0 19 16, rodt_lo3 15 12, rodt_lo2 11 8, rodt_lo1 7 4, rodt_lo0 3 0

REG = $scratch_LMC0_WODT_CTL0 8
REG_FIELD = $scratch_LMC0_WODT_CTL0 wodt_hi3 31 28, wodt_hi2 27 24, wodt_hi1 23 20, wodt_hi0 19 16, wodt_lo3 15 12, wodt_lo2 11 8, wodt_lo1 7 4, wodt_lo0 3 0

