+q  // Enter quiet mode
+mon
//___________________________________________________________________
// Script file for selecting one of the cnMIPS cores within the
// Cavium Networks OCTEON processor.  This script expects exactly
// one parameter to be passed in, which is the CPU number (0-15).
//___________________________________________________________________
//
if $$0 == 0  {dv "cpu_select.cmd expected one parameter (0-15)\n"; da CPU; goto EXIT}
//
if (@.4MAJIC_DO_IJTS == 0) {goto CPU_SELECT}
//
dv "This debug session has already been assigned to CPU %d\n", (@.4MAJIC_DO_IJTS - 1)
goto EXIT
//
//
// Select the CPU by its corresponding Test Access Port (TAP) position
//
:CPU_SELECT
if (0n\$$1\ == 0n00) {eo Ice_Jtag_Tap_Select =  1; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n01) {eo Ice_Jtag_Tap_Select =  2; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n02) {eo Ice_Jtag_Tap_Select =  3; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n03) {eo Ice_Jtag_Tap_Select =  4; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n04) {eo Ice_Jtag_Tap_Select =  5; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n05) {eo Ice_Jtag_Tap_Select =  6; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n06) {eo Ice_Jtag_Tap_Select =  7; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n07) {eo Ice_Jtag_Tap_Select =  8; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n08) {eo Ice_Jtag_Tap_Select =  9; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n09) {eo Ice_Jtag_Tap_Select = 10; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n10) {eo Ice_Jtag_Tap_Select = 11; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n11) {eo Ice_Jtag_Tap_Select = 12; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n12) {eo Ice_Jtag_Tap_Select = 13; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n13) {eo Ice_Jtag_Tap_Select = 14; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n14) {eo Ice_Jtag_Tap_Select = 15; goto CPU_SELECT_PT2}
if (0n\$$1\ == 0n15) {eo Ice_Jtag_Tap_Select = 16; goto CPU_SELECT_PT2}
dv "CPU must be in the range 0-15\n"
doq Trgt_CPU_State
doq Ice_Jtag_Tap_Select
goto EXIT
//
:CPU_SELECT_PT2
if (@.4MAJIC_DO_IJTS != 0) {goto CPU_SELECT_PT3}
// CPU not selected
doq Ice_Jtag_Tap_Select
+edb; eo EDB_Title_Name = "No CPU"; -edb
goto EXIT
//
:CPU_SELECT_PT3
// CPU selected successfully, set the window title and read the
// appropriate register definition file
+edb
if (\$$1\ < 10) {eo EDB_Title_Name = "CPU 0\$$1\"} {eo EDB_Title_Name = "CPU \$$1\"}
-edb
ed $proc_rev = @prid.rev
if (@$proc_rev < 2) { fr rd majic-ejtag-cn50xx.rd } /* else */ { fr rd majic-ejtag-cn50xx.rd }
if (@$proc_rev < 2) { fr rd majic-ejtag-cn50xx-lmc.rd } /* else */ { fr rd majic-ejtag-cn50xx-lmc.rd }
dd ebase.cpunum, d
//
:EXIT
-mon
//
// <eof>
