+q  // Enter quiet mode
+mon
//___________________________________________________________________
// startice.cmd: Created by MAJIC Setup Wizard version 3.6b
// Creation Date: 4/15/2005
// Processor type: cnMIPS -vcnMIPS
// Project: CN50xx-EVB-HS5
// Description: Cavium Octeon CN50xx-EVB-HS5 Reference Platform
//              FOR USE WITH EDT 2.4A OR LATER SOFTWARE ONLY.
//___________________________________________________________________
dv "Reading startice.cmd file\n"
//
// Software Settings
//
eo semi_hosting_enabled = on   // Semihosting support
//
// Target Information Options
//
eo trgt_resets_jtag     = no   // Target reset does not reset JTAG controller
//
// MAJIC Settings
//
eo ice_jtag_clock_freq  = 40   // JTAG clock frequency (MHz)
eo ice_jtag_use_trst    = on   // Controls whether MAJIC drives the TRST* signal
eo ice_reset_output     = off  // reset command does not pulse MAJIC's reset output
eo load_entry_pc        = off  // Controls whether PC register is loaded w/the entry point of loaded program
eo reset_at_load        = off  // Controls whether processor reset occurs before a program is downloaded
//
// Do NOT enable power sensor until after the MAJIC_JTAG_INIT1 descriptor is
// set.  On the first connection, the sensor will remain off until enabled in
// sg590.cmd.  On subsequent concurrent debug sessions, it will
// remain as set by the initial session.
//
// eo ice_power_sense   = OFF  // Leave power monitor disabled until board init file (off is default)
//
// Aliases for displaying the TLB contents and translating a virtual address
//
ea MMU_DUMP fr c mmu_dump64.cmd
ea MMU_XLATE fr c mmu_xlate.cmd
//
// Run board initialization command file
//
dv "Reading sg590.cmd\n"
fr c sg590.cmd
dv "Finished reading sg590.cmd\n"
//
dv "Finished reading startice.cmd\n"
-mon
