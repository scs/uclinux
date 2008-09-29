//+q  // Enter quiet mode
+mon
//___________________________________________________________________
// MAJIC Board initialization file for
// Cavium Networks CN50xx-EVB-HS5 Reference Platform
// Processor type: cnMIPS -vcnMIPS
// Project: CN50xx-EVB-HS5
// Description: Cavium Octeon CN50xx-EVB-HS5 Reference Platform
// 							FOR USE WITH EDT 2.4A OR LATER SOFTWARE ONLY.
//
// NOTES: The user should make the following adaptations to port
//        this file to the final target board:
//
//        1. If your board has a different memory configuration
//           than the reference platform, then you may need to
//           update the memory configuration (MC) table.
//           See 'NOTE #1' below.
//        2. If your target board requires any special MAJIC
//           settings, they should be added to the end of the
//           ONE_TIME_SETUP section.  See 'NOTE #2' below.
//        3. If you plan to use the EPIFLASH flash programming
//           utility, then you may need to change the address
//           where it's loaded.  See 'NOTE #3' below.
//        4. If your board has a different memory configuration
//           than the reference platform, then you may need to
//           modify the memory controller initialization script
//           accordingly.  See 'NOTE #4' below.
//
// If you rename this file to match your board's name, then don't
// forget to rename all references to it within this file and the
// startice.cmd file.
//___________________________________________________________________
//
if $$0 == 0 { goto ONE_TIME_SETUP }     // If NO parameters passed, goto One Time Setup logic
if $$1 == 1 { goto USER_INIT_RTI }      // If 1st parameter passed == 1, Reset Target and Initialize
if $$1 == 2 { goto USER_INIT_RTNI }     // If 1st parameter passed == 2, Reset Target w/o Initialize
if $$1 == 3 { goto USER_INIT_TI }       // If 1st parameter passed == 3, Target Initialize w/o reset
if $$1 == 4 { goto EPIFLASH }           // If 1st parameter passed == 4, run epi flash utility
goto EXIT
//___________________________________________________________________
:ONE_TIME_SETUP
//
ea RTI      fr c sg590.cmd 1   // RTI  runs USER_INIT_RTI script  (Reset Target and Initialize)
ea RTNI     fr c sg590.cmd 2   // RTNI runs USER_INIT_RTNI script (Reset Target w/o Initialize)
ea TI       fr c sg590.cmd 3   // TI   runs USER_INIT_TI script   (Target Initialize w/o reset)
ea EPIFLASH fr c sg590.cmd 4   // EPIFLASH runs EPIFLASH script   (run epiflash utility)
//
ea NOLOAD   EO load_entry_pc=off; EO reset_at_load=off
ea LOAD     EO load_entry_pc=on;  EO reset_at_load=on
ea RemapFlash ed MIO_BOOT_REG_CFG0.base =0x1c00; dv "\nFlash remapped to 0xbc000000 to allow writing the whole 8MB\n"
//
// GSTOP sets up the global stop conditions by reading the gstop.cmd script
ea GSTOP    fr c gstop
//
// Physical Memory Configuration
//
mc *:P, inv     // start with all *physical* memory (*:P) marked as invalid
//
// NOTE #1 -- Change the address ranges below to match the  *physical*
//            address ranges of your ROM/flash and RAM areas.  Add more
//            MC commands as necessary for each memory mapped area.
//
// WARNING:   DO NOT confuse kseg0/kseg1 with physical space.  Make sure
//            to use physical addresses in the MC table, not kseg0/kseg1.
//
// Address Range                      PWE  Access Width  RO/RW
// ---------------------------------- ---- ------ ------ -----
MC 0000000000000:P   000000FFFFFFF:P ,PWE, JAM,   DW=64, RW  // First 256 MB of DRAM
MC 0000010000000:P   000001FFFFFFF:P ,PWD, JAM,   DW=08, RW  // Boot Bus
MC 0000020000000:P   00003FFFFFFFF:P ,PWE, JAM,   DW=64, RW  // All DRAM above 512 MB
MC 0000410000000:P   000041FFFFFFF:P ,PWE, JAM,   DW=64, RW  // Second 256 MB of DRAM
MC 1000010000000:P   100001FFFFFFF:P ,PWD, JAM,   DW=08, RW  // Boot Bus (alias)
MC 1010000000000:P   1FF0FFFFFFFFF:P ,PWD, JAM,   DW=64, RW  // CSRs, I/O Bus Devices
MC 1190000000000:P   1190FFFFFFFFF:P ,PWD, JAM,   DW=32, RW  // PCI CFG/IACK/Spec. (LE Addr)
MC 11A0000000000:P   11A0FFFFFFFFF:P ,PWD, JAM,   DW=32, RW  // PCI I/O (subdid=2) (LE Addr)
MC 11B0000000000:P   11B0FFFFFFFFF:P ,PWE, JAM,   DW=64, RW  // PCI Mem (subdid=3) (LE Addr)
MC 11C0000000000:P   11C0FFFFFFFFF:P ,PWE, JAM,   DW=64, RW  // PCI Mem (subdid=4) (LE Addr)
MC 11D0000000000:P   11D0FFFFFFFFF:P ,PWE, JAM,   DW=64, RW  // PCI Mem (subdid=5) (LE Addr)
MC 11E0000000000:P   11E0FFFFFFFFF:P ,PWE, JAM,   DW=64, RW  // PCI Mem (subdid=6) (LE Addr)
MC 11F0000001100:P   11F000000119F:P ,PWD, JAM,   DW=32, RW  // PCI CSRs, 32-bit   (LE Addr)
MC 11F0000001800:P   11F00000018FF:P ,PWE, JAM,   DW=32, RW  // PCI CFG (Local)    (LE Addr)
MC 16F0000000000:P   16F0FFFFFFFFF:P ,PWD, JAM,   DW=32, RW  // USB CSRs, 32-bit   (LE Addr)
MC 000001FC00000:P   000001FFFFFFF:P ,PWD, JAM,   DW=8, RO  // Boot flash
MC 000001F400000:P   000001FFFFFFF:P ,PWD, JAM,   DW=8, RW  // Boot flash (Remapped)
MC ffFFFFFFFFF8000:P   ffFFFFFFFFF8000:P ,PWE, JAM,   DW=64, RW  // CVMSEG LM
MC ffFFFFFFFFFA200:P   ffFFFFFFFFFA207:P ,PWD, JAM,   DW=64, RW  // CVMSEG IO
//
//
//        ____User Supplied One Time Commands Go Here____
//
// NOTE #2 -- If your target board requires any special MAJIC settings
//            (e.g. special JTAG initialization), add the commands to
//            make those settings here.
//
//
//eo Ice_Multi_Session = on			// Allow multiple debugger connections
//
// Read Cavium specific register definition files
//
//
// Assign an ID with a unique number for each possible memory configuration.
//
ed $meminit_none                              = 0
ed $meminit_ddr2_WD2RE01GX818_800I_PE_400MHz  = 1
ed $meminit_ddr2_WD2RE01GX818_800I_PE_800MHz  = 2
ed $meminit_ddr2_WD2UE01GX818_800I_PE_400MHz  = 3
ed $meminit_ddr2_WD2UE01GX818_800I_PE_800MHz  = 4
ed $meminit_sg590                             = 5
//
// Now select the desired memory configuration using one of the IDs above.
//
//    ed $meminit_select = @$meminit_none
//    ed $meminit_select = @$meminit_ddr2_WD2RE01GX818_800I_PE_400MHz
//    ed $meminit_select = @$meminit_ddr2_WD2RE01GX818_800I_PE_800MHz
//    ed $meminit_select = @$meminit_ddr2_WD2UE01GX818_800I_PE_400MHz
//    ed $meminit_select = @$meminit_ddr2_WD2UE01GX818_800I_PE_800MHz
ed $meminit_select = @$meminit_sg590
//
// Initialize all 16 TAPs to "Probe Boot" or "Normal Boot" mode.  The first
// word is the total number of IR bits,  The second through fourth words are
// the IR bit values (LS 5 bits of first word correspond to TAP1, which is
// CPU0, the next 5 bits are TAP2...).  The last two words below are the
// shift data count and shift data value (but there is no data for these
// JTAG operations).
//
// For more information, please see the "MAJIC Support for Multi-TAP JTAG
// Configurations" application note.
//
// Only enable *ONE* of the following two initialization descriptors
//
//   ew MAJIC_JTAG_INIT1 = (0n16*5), 0x18c6318c, 0xc6318c63, 0x6318, 0, 0 // Set all 16 TAPs to "Probe Boot" mode.
ew MAJIC_JTAG_INIT1 = (0n16*5), 0x5ad6b5ad, 0xd6b5ad6b, 0x6b5a, 0, 0 // Set all 16 TAPs to "Normal Boot" mode.
//
// Now that JTAG Init sequence is defined, it's safe to enable power monitor
//
eo ice_power_sense = VREF // Sense target voltage level on VREF pin
//
// Create command aliases for selecting the CPU to debug by its position
// on the JTAG scan chain.  If the TAP is already connected, then report
// an error because it's not normally safe to change the TAP connection
// during a debug session.
//
ea CPU   fr c cpu_select			/* Select CPU (takes one parameter 0-15) */
ea CPUID +mon; dd ebase.cpunum, d; -mon		/* Display selected CPU                  */
//
ea CPU1  dv "\"CPU1\" syntax is deprecated, please use \"CPU 1\"\n"
ea CPU2  dv "\"CPU2\" syntax is deprecated, please use \"CPU 2\"\n"
ea CPU3  dv "\"CPU3\" syntax is deprecated, please use \"CPU 3\"\n"
ea CPU4  dv "\"CPU4\" syntax is deprecated, please use \"CPU 4\"\n"
ea CPU5  dv "\"CPU5\" syntax is deprecated, please use \"CPU 5\"\n"
ea CPU6  dv "\"CPU6\" syntax is deprecated, please use \"CPU 6\"\n"
ea CPU7  dv "\"CPU7\" syntax is deprecated, please use \"CPU 7\"\n"
ea CPU8  dv "\"CPU8\" syntax is deprecated, please use \"CPU 8\"\n"
ea CPU9  dv "\"CPU9\" syntax is deprecated, please use \"CPU 9\"\n"
ea CPU10 dv "\"CPU10\" syntax is deprecated, please use \"CPU 10\"\n"
ea CPU11 dv "\"CPU11\" syntax is deprecated, please use \"CPU 11\"\n"
ea CPU12 dv "\"CPU12\" syntax is deprecated, please use \"CPU 12\"\n"
ea CPU13 dv "\"CPU13\" syntax is deprecated, please use \"CPU 13\"\n"
ea CPU14 dv "\"CPU14\" syntax is deprecated, please use \"CPU 14\"\n"
ea CPU15 dv "\"CPU15\" syntax is deprecated, please use \"CPU 15\"\n"
//
CPU 0	// Attempt to select CPU 0 (only works on first debug session)


fr rd majic-ejtag-cn50xx
fr rd majic-ejtag-cn50xx-lmc


//
//  If the CPU 0 selection was accepted, and the debugger was not started
//  in non-intrusive mode, then reset and initialize the target.  Otherwise
//  skip the initialization because it's not appropriate or not desirable
//  to do so.
//
ew $trgt_cpu_state = @.1MAJIC_DO_CPU_STATE
if (@.4$trgt_cpu_state == 1) {goto USER_INIT_RTI}  // Reset and initialize
//
dv "Target Initialization commands skipped due to CPU state:  "
doq Trgt_CPU_State
dv  "\nNote:  Enter  \"CPU n\"  to select the CPU core for this debug session\n\n"
goto EXIT
//
//___________________________________________________________________
:EPIFLASH
//
//         ____User Supplied Flash Programming Commands Go Here____
//
// NOTE #3 --  If your target board requires any special initialization
//             commands to prepare for running the epiflash programming
//             utility, add those commands here.
//
//             Be sure the to pass the address matching the ...ram_* directory
//             suitable for your RAM area to the epiflash.cmd script.  If
//             your target board supports both endians, but flash programming
//             will only work in one of them, it is recommended to add the
//             optional third parameter specifying the required programming
//             endian (be or le).  See comments in ./bin/epiflash.cmd for
//             details.
//
// Remap 8 meg flash part to bottom of boot bus
RemapFlash
//
// Expand MC table accordingly
MC 000001C000000:P   000001FFFFFFF:P ,PWD, JAM,   DW=64, RO  // Boot flash (Remapped)
//
LOAD
eo reset_at_load = on
//
fr c epiflash.cmd epiflash.elf 0xA0001000 be
//
NOLOAD
eo reset_at_load = off
//
goto EXIT
//
//___________________________________________________________________
:USER_INIT_RTNI
//
if (@.4MAJIC_DO_IJTS > 1) {dv "Target should only be reset from the CPU 0 debug session\n"; goto EXIT}
dv "Executing RTNI Commands\n"
rt
//
//        ____User Supplied RTNI Commands Go Here____
//
//
goto EXIT                               // Skip Target Init
//
//___________________________________________________________________
:USER_INIT_RTI
//
if (@.4MAJIC_DO_IJTS > 1) {dv "Target should only be reset from the CPU 0 debug session\n"; goto EXIT}
dv "Executing RTI commands\n"
rt
//
//        ____User Supplied RTI Commands Go Here____
//
//
// Fall through to TI part of RTI
//___________________________________________________________________
:USER_INIT_TI
//
ew $trgt_cpu_state = @.1MAJIC_DO_CPU_STATE
if (@.4$trgt_cpu_state != 1) { dv "Target Initialization commands skipped due to CPU state:  "; doq TCS; doq IJTC; doq IJTS; goto EXIT }
dv "Initializing target...\n"
//
//  Memory Controller Setup
//
// NOTE #4 -- If your board has a different memory configuration than
//            the reference board, then you may need to adapt the
//            memory controller initialization script accordingly.
//            These settings should match the settings used by your
//            boot code during its hardware initialization phase.
//
//  Run the memory controller initialization script which was selected
//  via the  $meminit_select  setting (above).
//
if (@$meminit_select == @$meminit_none) {dv "Target initialization skipped: "; dd $meminit_select; goto EXIT}
//
if (@$meminit_select == @$meminit_ddr2_WD2RE01GX818_800I_PE_400MHz) {fr c ddr2_WD2RE01GX818_800I_PE_400MHz}
if (@$meminit_select == @$meminit_ddr2_WD2RE01GX818_800I_PE_800MHz) {fr c ddr2_WD2RE01GX818_800I_PE_800MHz}
if (@$meminit_select == @$meminit_ddr2_WD2UE01GX818_800I_PE_400MHz) {fr c ddr2_WD2UE01GX818_800I_PE_400MHz}
if (@$meminit_select == @$meminit_ddr2_WD2UE01GX818_800I_PE_800MHz) {fr c ddr2_WD2UE01GX818_800I_PE_800MHz}
if (@$meminit_select == @$meminit_sg590) {fr c ddr2_sg590}
//
//
//        ____User Supplied Target Init Commands Go Here____
//
//
dv "Target initialization completed.\n"
//
//___________________________________________________________________
:EXIT
//
//
-mon
// <eof>
