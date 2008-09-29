//  The gstop.cmd script sets up the global stop conditions.  These
//  options are bit flags, where bit 0 corresponds to CPU 0, bit 1
//  is for CPU 1, ...  Use the  "dov ice_gs*"  command for details
//  on these options.
//
//  When read in any debug session, they apply to all debug sessions.
//  However, the ice_gstop_mask* and ice_gstop_swbp options are only
//  applied to a CPU when execution is started on that CPU (i.e. not
//  if the option is set while already running).  Likewise, the
//  ice_gstop_pulse* options are only applied when execution stops
//  on the given CPU.
//
EO ice_gstop_mask_0   = 0x5555      // Global stop channel 0 mask
EO ice_gstop_mask_1   = 0xaaaa      // Global stop channel 1 mask
EO ice_gstop_mask_2   = 0x0         // Global stop channel 2 mask
EO ice_gstop_pulse_0  = 0x0         // Global stop channel 0 pulse
EO ice_gstop_pulse_1  = 0x1000      // Global stop channel 1 pulse
EO ice_gstop_pulse_2  = 0x0         // Global stop channel 2 pulse
EO ice_gstop_swbp     = 0x0         // Global stop on software breakpoint
//
DO ice_gs*
//
// <eof>
