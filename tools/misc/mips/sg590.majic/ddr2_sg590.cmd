+q  // Enter quiet mode
+mon
ed $verbosity = 0
//
// Memory Controller configuration for SnapGear SG590 board.
//
dv "Initializing target using ddr2_sg590.cmd\n"
//
// SnapGear SG590
// OCTEON CN50XX-SCP revision: 0, Core clock: 600 MHz, DDR clock: 200 MHz (400 Mhz data rate)
//
//
// If you need a different memory configuration and you have a working
// board that configures the memory controller with other firmware, such
// as the Octeon bootloader, you may capture the final LMC settings and
// merge them into this file.  This command file will use that information
// to perform the proper steps to initialize the memory controller.
//
// Use the display_lmc.cmd command file to capture the settings.  When you
// run the display_lmc command file it will write out the file
// "display_lmc.log" containing the contents of the memory controller
// registers. The following command is used to run the display_lmc.cmd
// command file.
//
// MON> fr c display_lmc
//
// ===============================================================
// .lmc0_comp_ctl  00000000F000F000 (nctl_csr=f nctl_dat=0 pctl_csr=f pctl_dat=0)
// .lmc0_ctl  00000000637C8654 (ddr__nctl=6 ddr__pctl=3 slow_scf XOR_BANK
//                              max_write_batch=f pll_bypass RDIMM_ENA r2r_slot
//                              inorder_mwf inorder_mrf dreset MODE32B FPRCH2 bprch
//                              sil_lat=1 tskw=1 qs_dic=1 dic=0)
// .lmc0_ctl1  0000000000000200 (SIL_MODE dcc_enable data_layout=0)
// .lmc0_ddr2_ctl  0000000040800101 (bank8 BURST8 addlat=0 pocas bwcnt twr=2 silo_hc
//                              ddr_eof=0 tfaw=0 crip_mode ddr2t odt_ena QDLL_ENA
//                              dll90_vlu=0 dll90_byp rdqs DDR2)
// .lmc0_delay_cfg  0000000000000C03 (dq=3 cmd=0 clk=3)
// .lmc0_dual_memcfg  0000000000030000 (bank8 row_lsb=3 cs_mask=0)
// .lmc0_mem_cfg0  0000000020000643 (reset silo_qc BUNK_ENA ded_err=0 sec_err=0
//                              intr_ded_ena intr_sec_ena tcl=0 ref_int=3
//                              pbank_lsb=2 row_lsb=0 ECC_ENA INIT_START)
// .lmc0_mem_cfg1  0000000028CC6469 (comp_bypass trrd=2 caslat=4 tmrd=3 trfc=6 trp=3
//                              twtr=2 trcd=3 tras=9)
// .lmc0_pll_ctl  00000000040BC010 (fasten_n div_reset RESET_N clkf=2f clkr=0 en16 EN12
//                              en8 en6 en4 en2)
// .lmc0_pll_status  0000000034C00000 (ddr__nctl=6 ddr__pctl=13 rfslip fbslip)
// .lmc0_rodt_comp_ctl  0000000000010207 (ENABLE nctl=2 pctl=7)
// .lmc0_rodt_ctl  0000000000000000 (rodt_hi3=0 rodt_hi2=0 rodt_hi1=0 rodt_hi0=0
//                              rodt_lo3=0 rodt_lo2=0 rodt_lo1=0 rodt_lo0=0)
// .lmc0_wodt_ctl0  0000000000000011 (wodt_hi3=0 wodt_hi2=0 wodt_hi1=0 wodt_hi0=0
//                              wodt_lo3=0 wodt_lo2=0 wodt_lo1=1 wodt_lo0=1)
//
//
//
// Final settings: Captured from board
//
ed      $final_lmc0_comp_ctl = 0x00000000f000f000
ed           $final_lmc0_ctl = 0x00000000617c0658
ed          $final_lmc0_ctl1 = 0x0000000000000200
ed      $final_lmc0_ddr2_ctl = 0x0000000000820501
ed     $final_lmc0_delay_cfg = 0x0000000000002C09
ed   $final_lmc0_dual_memcfg = 0x0000000000030000
ed      $final_lmc0_mem_cfg0 = 0x0000000040000621
ed      $final_lmc0_mem_cfg1 = 0x0000000026cc6448
ed       $final_lmc0_pll_ctl = 0x00000000040bc010
ed    $final_lmc0_pll_status = 0x0000000034400000
ed $final_lmc0_rodt_comp_ctl = 0x0000000000010207
ed      $final_lmc0_rodt_ctl = 0x0000000000000000
ed     $final_lmc0_wodt_ctl0 = 0x0000000000010001
// ===============================================================
//
//
// Create scratch copies of the LMC registers in probe memory
fr rd scratch_lmc
//
// ----------------------------------------------------------------
// The next few examples show how to override select values used in
// this configuration.  Uncomment and modify these settings or add
// others to adapt this configuration to other board designs.
//
// The "board delay" parameters are the most likely settings to vary
// across different board designs as long as they use similar DIMMs.
// These settings should be modified to suit the the etch lengths
// used in the DRAM paths.
//
/// ed $scratch_lmc0_ctl = @$final_lmc0_ctl
/// ed $scratch_lmc0_ctl.tskw = 0
/// ed .lmc0_ctl = @$scratch_lmc0_ctl
//
/// ed $scratch_lmc0_ddr2_ctl = @$final_lmc0_ddr2_ctl
/// ed $scratch_lmc0_ddr2_ctl.silo_hc = 1
/// ed .lmc0_ddr2_ctl = @$scratch_lmc0_ddr2_ctl
//
/// ed $scratch_lmc0_mem_cfg0 = @$final_lmc0_mem_cfg0
/// ed $scratch_lmc0_mem_cfg0.silo_qc = 1
/// ed .lmc0_mem_cfg0 = @$scratch_lmc0_mem_cfg0
//
/// ed $scratch_lmc0_delay_cfg = @$final_lmc0_delay_cfg
/// ed $scratch_lmc0_delay_cfg.clk = 4
/// ed $scratch_lmc0_delay_cfg.cmd = 0
/// ed $scratch_lmc0_delay_cfg.dq  = 2
/// ed .lmc0_delay_cfg = @$scratch_lmc0_delay_cfg
//
// ----------------------------------------------------------------
//
//        /*
//         * DCLK Initialization Sequence
//         *
//         * When the reference-clock inputs to the LMC (DDR2_REF_CLK_P/N) are
//         * stable, perform the following steps to initialize the DCLK.
//         *
//         * 1. Write LMC_CTL[DRESET]=1, LMC_DDR2_CTL[QDLL_ENA]=0.
//         */
//
ed $scratch_lmc0_ctl = @$final_lmc0_ctl
ed $scratch_lmc0_ctl.dreset = 1
ed .lmc0_ctl = @$scratch_lmc0_ctl
if (@$verbosity > 0) {dd .lmc0_ctl}
//
ed $scratch_lmc0_ddr2_ctl = @$final_lmc0_ddr2_ctl
ed $scratch_lmc0_ddr2_ctl.qdll_ena = 0
ed .lmc0_ddr2_ctl = @$scratch_lmc0_ddr2_ctl
if (@$verbosity > 0) {dd .lmc0_ddr2_ctl}
//
//        /*
//         * 2. Write LMC_PLL_CTL[CLKR, CLKF, EN*] with the appropriate values,
//         *    while writing LMC_PLL_CTL[RESET_N] = 0, LMC_PLL_CTL[DIV_RESET] = 1.
//         *    LMC_PLL_CTL[CLKR, CLKF, EN*] values must not change after this
//         *    point without restarting the DCLK initialization sequence.
//         */
//
//        /* CLKF = (DCLK/DREF) * (CLKR+1) * EN(2, 4, 6, 8, 12, 16) - 1 */
//
ed $scratch_lmc0_pll_ctl = @$final_lmc0_pll_ctl
ed $scratch_lmc0_pll_ctl.reset_n = 0
ed $scratch_lmc0_pll_ctl.div_reset = 1
ed .lmc0_pll_ctl = @$scratch_lmc0_pll_ctl
if (@$verbosity > 0) {dd .lmc0_pll_ctl}
//
//        /*
//         * 5. Write LMC_PLL_CTL[RESET_N] = 1 while keeping LMC_PLL_CTL[DIV_RESET]
//         *    = 1. LMC_PLL_CTL[RESET_N] must not change after this point without
//         *    restarting the DCLK initialization sequence.
//         */
//
ed $scratch_lmc0_pll_ctl = @$final_lmc0_pll_ctl
ed $scratch_lmc0_pll_ctl.div_reset = 1
ed .lmc0_pll_ctl = @$scratch_lmc0_pll_ctl
if (@$verbosity > 0) {dd .lmc0_pll_ctl}
//
//        /*
//         * 8. Write LMC_PLL_CTL[DIV_RESET] = 0. LMC_PLL_CTL[DIV_RESET] must not
//         *    change after this point without restarting the DCLK initialization
//         *    sequence.
//         */
//
ed $scratch_lmc0_pll_ctl = @$final_lmc0_pll_ctl
ed $scratch_lmc0_pll_ctl.div_reset = 0
ed .lmc0_pll_ctl = @$scratch_lmc0_pll_ctl
if (@$verbosity > 0) {dd .lmc0_pll_ctl}
//
//        /*
//         * DRESET Initialization Sequence
//         *
//         * The DRESET initialization sequence cannot start unless DCLK is stable
//         * due to a prior DCLK initialization sequence. Perform the following
//         * steps to initialize DRESET.
//         *
//         * 1. Write LMC_CTL[DRESET] = 1 and LMC_DDR2_CTL[QDLL_ENA] = 0.
//         */
//
ed $scratch_lmc0_ctl = @.lmc0_ctl
ed $scratch_lmc0_ctl.dreset = 1
ed .lmc0_ctl = @$scratch_lmc0_ctl
if (@$verbosity > 0) {dd .lmc0_ctl}
//
ed $scratch_lmc0_ddr2_ctl = @$final_lmc0_ddr2_ctl
ed $scratch_lmc0_ddr2_ctl.qdll_ena = 0
ed .lmc0_ddr2_ctl = @$scratch_lmc0_ddr2_ctl
if (@$verbosity > 0) {dd .lmc0_ddr2_ctl}
//
ed $scratch_lmc0_ddr2_ctl = @$final_lmc0_ddr2_ctl
ed $scratch_lmc0_ddr2_ctl.qdll_ena = 1
ed .lmc0_ddr2_ctl = @$scratch_lmc0_ddr2_ctl
if (@$verbosity > 0) {dd .lmc0_ddr2_ctl}
//
//       /*
//         * 5. Write LMC_CTL[DRESET] = 0. LMC_CTL[DRESET] must not change after
//         *    this point without restarting the DRAM-controller and/or DRESET
//         *    initialization sequence.
//         */
//
ed $scratch_lmc0_ctl = @.lmc0_ctl
ed $scratch_lmc0_ctl.dreset = 0
ed .lmc0_ctl = @$scratch_lmc0_ctl
if (@$verbosity > 0) {dd .lmc0_ctl}
//
//        /*
//         * 2. Write LMC_CTL, LMC_CTL1, LMC_MEM_CFG1, LMC_DDR2_CTL,
//         * LMC_RODT_CTL, LMC_DUAL_MEMCFG, and LMC_WODT_CTL with appropriate
//         * values, if necessary. Refer to Sections 2.3.4, 2.3.5, and 2.3.7 regarding
//         * these registers (and LMC_MEM_CFG0).
//         */
//
ed $scratch_lmc0_ctl1 = @.lmc0_ctl1
ed $scratch_lmc0_ctl1.sil_mode = 1
ed .lmc0_ctl1 = @$scratch_lmc0_ctl1
if (@$verbosity > 0) {dd .lmc0_ctl1}
//
//    /* On pass2 we can count DDR clocks, and we use this to correct
//    ** the DDR clock that we are passed.
//    ** We must enable the memory controller to count DDR clocks. */
//
ed $scratch_lmc0_mem_cfg0 = 0
ed $scratch_lmc0_mem_cfg0.init_start = 1
ed .lmc0_mem_cfg0 = @$scratch_lmc0_mem_cfg0
if (@$verbosity > 0) {dd .lmc0_mem_cfg0}
//
//
//     * 1. Write LMC_CTL with [DRESET] = 1, [PLL_BYPASS] = user_value, and
//     * [PLL_DIV2] = user_value.
//
ed $scratch_lmc0_ctl = @$final_lmc0_ctl
ed $scratch_lmc0_ctl.dreset = 0
ed .lmc0_ctl = @$scratch_lmc0_ctl
if (@$verbosity > 0) {dd .lmc0_ctl}
//
//    /* 4. Write LMC_DDR2_CTL[QDLL_ENA] = 1. */ /* Is it OK to write 0 first? */
//
ed $scratch_lmc0_ddr2_ctl = @$final_lmc0_ddr2_ctl
ed $scratch_lmc0_ddr2_ctl.qdll_ena = 0
ed .lmc0_ddr2_ctl = @$scratch_lmc0_ddr2_ctl
if (@$verbosity > 0) {dd .lmc0_ddr2_ctl}
//
ed $scratch_lmc0_ddr2_ctl = @$final_lmc0_ddr2_ctl
ed $scratch_lmc0_ddr2_ctl.qdll_ena = 1
ed .lmc0_ddr2_ctl = @$scratch_lmc0_ddr2_ctl
if (@$verbosity > 0) {dd .lmc0_ddr2_ctl}
//
//    /*
//     * Next, boot software must re-initialize the LMC_MEM_CFG1, LMC_CTL, and
//     * LMC_DDR2_CTL CSRs, and also the LMC_WODT_CTL and LMC_RODT_CTL
//     * CSRs. Refer to Sections 2.3.4, 2.3.5, and 2.3.7 regarding these CSRs (and
//     * LMC_MEM_CFG0).
//     */
//
ed .lmc0_wodt_ctl0 = @$final_lmc0_wodt_ctl0
if (@$verbosity > 0) {dd .lmc0_wodt_ctl0}
//
//
ed .lmc0_rodt_ctl = @$final_lmc0_rodt_ctl
if (@$verbosity > 0) {dd .lmc0_rodt_ctl}
//
ed .lmc0_ddr2_ctl = @$final_lmc0_ddr2_ctl
if (@$verbosity > 0) {dd .lmc0_ddr2_ctl}
//
//
ed .lmc0_delay_cfg = @$final_lmc0_delay_cfg
if (@$verbosity > 0) {dd .lmc0_delay_cfg}
//
//
ed .lmc0_mem_cfg1 = @$final_lmc0_mem_cfg1
if (@$verbosity > 0) {dd .lmc0_mem_cfg1}
//
//
ed .lmc0_comp_ctl = @$final_lmc0_comp_ctl
if (@$verbosity > 0) {dd .lmc0_comp_ctl}
//
//
ed .lmc0_mem_cfg0 = 0
if (@$verbosity > 0) {dd .lmc0_mem_cfg0}
//
//
ed .lmc0_rodt_comp_ctl = @$final_lmc0_rodt_comp_ctl
if (@$verbosity > 0) {dd .lmc0_rodt_comp_ctl}
//
//
//    /*
//     * Finally, software must write the LMC_MEM_CFG0 register with
//     * LMC_MEM_CFG0[INIT_START] = 1. At that point, CN31XX hardware initiates
//     * the standard DDR2 initialization sequence shown in Figure 2.
//     */
//
ed $scratch_lmc0_mem_cfg0 = @$final_lmc0_mem_cfg0
ed $scratch_lmc0_mem_cfg0.init_start = 0
ed $scratch_lmc0_mem_cfg0.sec_err = ~0
ed $scratch_lmc0_mem_cfg0.ded_err = ~0
ed .lmc0_mem_cfg0 = @$scratch_lmc0_mem_cfg0
if (@$verbosity > 0) {dd .lmc0_mem_cfg0}
//
//
ed $scratch_lmc0_mem_cfg0 = @.lmc0_mem_cfg0
ed $scratch_lmc0_mem_cfg0.init_start = 1
ed .lmc0_mem_cfg0 = @$scratch_lmc0_mem_cfg0
if (@$verbosity > 0) {dd .lmc0_mem_cfg0}
//
//
:EXIT
dv "Exiting ddr2_sg590.cmd ...\n"
if (@$verbosity > 0) {fw o -}
-mon
// <eof>
