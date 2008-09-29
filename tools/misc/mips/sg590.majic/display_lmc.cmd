+q  // Enter quiet mode
+mon
dv "Creating output file display_lmc.log\n"
fwo o display_lmc.log
//
dd      .lmc0_comp_ctl
dd           .lmc0_ctl
dd          .lmc0_ctl1
dd      .lmc0_ddr2_ctl
dd     .lmc0_delay_cfg
dd   .lmc0_dual_memcfg
dd      .lmc0_mem_cfg0
dd      .lmc0_mem_cfg1
dd       .lmc0_pll_ctl
dd    .lmc0_pll_status
dd .lmc0_rodt_comp_ctl
dd      .lmc0_rodt_ctl
dd     .lmc0_wodt_ctl0
//
dv "//\n"
dv "//\n"
dv "//\n"
dv "// Final settings: Captured from board\n"
dv "//\n"
//
dv "ed      $final_lmc0_comp_ctl = 0x%016x\n", @.lmc0_comp_ctl
dv "ed           $final_lmc0_ctl = 0x%016x\n", @.lmc0_ctl
dv "ed          $final_lmc0_ctl1 = 0x%016x\n", @.lmc0_ctl1
dv "ed      $final_lmc0_ddr2_ctl = 0x%016x\n", @.lmc0_ddr2_ctl
dv "ed     $final_lmc0_delay_cfg = 0x%016x\n", @.lmc0_delay_cfg
dv "ed   $final_lmc0_dual_memcfg = 0x%016x\n", @.lmc0_dual_memcfg
dv "ed      $final_lmc0_mem_cfg0 = 0x%016x\n", @.lmc0_mem_cfg0
dv "ed      $final_lmc0_mem_cfg1 = 0x%016x\n", @.lmc0_mem_cfg1
dv "ed       $final_lmc0_pll_ctl = 0x%016x\n", @.lmc0_pll_ctl
dv "ed    $final_lmc0_pll_status = 0x%016x\n", @.lmc0_pll_status
dv "ed $final_lmc0_rodt_comp_ctl = 0x%016x\n", @.lmc0_rodt_comp_ctl
dv "ed      $final_lmc0_rodt_ctl = 0x%016x\n", @.lmc0_rodt_ctl
dv "ed     $final_lmc0_wodt_ctl0 = 0x%016x\n", @.lmc0_wodt_ctl0
//
fw o -
dv "Created output file display_lmc.log\n"
-mon
// <eof>
