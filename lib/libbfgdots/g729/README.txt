G729ab Blackfin uClinux codec README
12 October 2006
David Rowe (subcontractor to Analog Devices)

Directories
-----------

doc        - original Analog doc file (pre uClinux port)
include    - include file u need to use G729A(B) libraries
script     - Perl script for flat-fdpic conversion plus some
             test files
src.orig   - original flat mode asm, slightly modified to support
             fdpic conversion by script.  Perform ALL asm changes here,
             not in src.fdpic.
src.simgot - partially converted asm code, used to incrementally test
             fdpic conversion scheme during development.  May be useful
             for testing if Perl script is developed further.
src.fdpic  - fdpic asm files, generated auto magically by Perl script from
             src.orig.  Do not modify any asm code in this directory.  It's
             OK to modify globals.txt and the Makefile.
 
Building the Libraries and Test Programs
----------------------------------------

1. Install Blackfin uClinux toolchain and add the path to PATH.  To
   build the .so version the toolchain needs to have the following
   patch (or CVS update to binutils) applied:

   http://blackfin.uclinux.org/tracker/?func=detail&aid=1752&group_id=18&atid=145
 
   This patch hides symbols in asm files (such as LOOP labels) by
   default.  Without this patch there will be many symbols that will
   fail to link correctly when programs using the .so (such as
   g789ab_testfdpic_so) are linked.  However the flat mode and
   statically linked fdpic programs will still link OK without this
   patch.

2. [host]$ cd test
   [host]$ make

   This will create libraries in the src directories, and several test
   programs in the test directory:

   src.orig/libg729.a   : flat mode lib
   src.simgot/libg729.a : simulated GOT flat mode lib (used for development)
   src.fdpic/libg729.a  : fdpic static lib
   src.fdpic/libg729.so : fdpic shared lib
  
   g729ab               : flat mode test program
   g729asimgot          : simulated GOT flat mode test program
   g729ab_fdpic         : fdpic test program, statically linked G729
   g729ab_fdpic_so      : fdpic test program, dynamically linked G729
   
Running the Test Programs
-------------------------

1. Download the entire "test_data" directory and the scripts
   "quick.sh" and "alltests.sh" to the target.

2. Download one or more of the programs "g729ab", "g729ab_fdpic",
   "g729ab_fdpic_so".  If you are testing the .so also download
   "libg729ab.so".

3. To run a quick test:

   root:/var/tmp> ./quick.sh g729ab_testfdpic
   Average MIPs: 6.60
   Average MIPs: 1.33
   Average MIPs: 4.69
   Average MIPs: 1.54
   root:/var/tmp>

   The four cases tested are G729A enc, G729A dec, G729AB enc, G729AB
   dec.  If there are no other messages the test passed.  It will stop
   with a "diff" error message if the vectors don't match, indicating
   a fail.

   The test above was run on a BF533 STAMP with write-back cache , 400MHz
   CCLK, 80MHz SCLK.  MIPs are measured based on cycles used, so are
   independent of the actual clock. 

   The same test on a BF537 STAMP with write-through cache, 500MHz CCLK,
   100MHz SCLK:

   root:/var/tmp> ./quick.sh g729ab_testfdpic
   Average MIPs: 8.02
   Average MIPs: 2.20
   Average MIPs: 5.91
   Average MIPs: 2.19
   root:/var/tmp>

   The difference is speed may be due to the write-through cache.

4. To run all the test vectors:

   root:/var/tmp> ./alltests.sh g729ab_testfdpic
   root:/var/tmp>

   As with the quick test - no output means the tests passed.

5. Test multi-channel operation:

   root:/var/tmp> ./g729ab_testfdpic --multi
   Multi-threaded test, 8 encoders and 8 decoders
   Average MIPs: 8.03
   Average MIPs: 8.71
   Average MIPs: 8.64
   Average MIPs: 8.65
   Average MIPs: 8.67
   Average MIPs: 8.67
   Average MIPs: 8.58
   Average MIPs: 8.58
   Average MIPs: 3.14
   Average MIPs: 3.10
   Average MIPs: 3.06
   Average MIPs: 3.02
   Average MIPs: 3.02
   Average MIPs: 2.94
   Average MIPs: 2.92
   Average MIPs: 2.88

   The test above was run on a BF533 STAMP with write-back cache, 400MHz
   CCLK, 80MHz SCLK.  The larger values are the average MIPs for each
   encoder, the smaller values are decoder threads.  If any of the threads
   failed to process correctly (as compared to the test vectors) an
   error message will be printed and the test terminated.

   The MIPs values are slightly higher than (3) above as they include
   some overhead for testing and file I/O.  Due to the design of the
   test program and threading model is was difficult to separate the
   pure G729 execution time from other work being done by the CPU.

   The purpose of the --multi mode is to prove simultaneous channels
   can run without interfering with each other (for example state
   variable clashing), rather than accurately measure MIPs.  Test (3)
   above is a better test for measuring MIPs as the test design
   guarantees that the entire CPU is available for the G729 code under
   test.

   This program starts 8 encoders and 8 decoders, each running a set
   of test data files.  The results of each thread are checked against
   the output test vectors files. In this mode (--multi flag) each
   thread models typical execution on a real time system, e.g.:

   ...
   encode
   sleep 10ms
   encode
   sleep 10ms
   ...

   In practice threads sleep most of the time, and only wake up when
   they are presented with input data from an I/O process.  Most of
   the time each thread is sleeping, in that time the CPU can process
   other threads.

Requirements
------------

The requirements for this work were:

REQ1/ Convert the flat mode G729AB assembler to fdpic.  Object code
compiled as fdpic can (i) be relocated to L1 for efficient operation
and (ii) be placed in a .so to support mixing of GPL with non-GPL
licensed code.

REQ2/ To reduce future maintenance develop a single code base than can
be used for flat and fdpic modes.

REQ3/ Use the minimum amount of L1 memory, for example 8 channels
shouldn't use 8 times the amount of L1 as 1 channel.

REQ4/ Develop an efficient threading model to support simultaneous
operation by multiple threads.  There should be no undue delays or
excessive CPU usage due to spin locks.

Flat to FDPIC Conversion
------------------------

The G729AB code consists of 12,000 lines of intricate hand-crafted
assembler.  This is is a large amount of very complex code in a very
difficult development environment (optimised assembler on an embedded
platform).  Any modifications to the source are likely to introduce
bugs that will be difficult and time consuming to find.  Therefore a
strong theme of this work was to minimise the need for modification to
the asm code.

The code is non-re-entrant, as all of the states are stored as globals
rather than offsets into a structure, for example:

       I0.H = sharp;
       I0.L = sharp;

To meet (REQ1) all of the global references need to be changed to the
form:

       R0 = [P3+sharp@GOT17M4];
       IO = [R0];	

In fdpic mode P3 is a dedicated GOT table pointer that must be
preserved.  However the flat mode asm uses every pointer register in
many routines, therefore to free P3 throughout the code would mean a
major re-write of the code, and large amounts of complex debugging.

After analysing the code it was discovered that M2 was rarely used -
this was therefore chosen as the GOT offset.  However this results in
more complex code for each variable lookup:

        [--SP] = R0;
        [--SP] = P3;
        P3 = M2;
        R0 = [P3+sharp@GOT17M4];
        I0 = R0
        P3 = [SP++];
        R0 = [SP++];

Note we save R0/P3 to the stack to make sure our look ups don't affect
operation of the surrounding code.  This resulted in more MIPs to
execute the code (especially with all code and variables in external
memory), however once placed in L1 the efficiency was acceptable (see
tests above).

There are a large number of global look ups that need to be converted
to fdpic.  However as the conversion of each look up was very similar
a Perl script (flat2fdpic.pl) was written to automate the process and
reduce the chance of error.  A Makefile is used to generate the fdpic
asm from the flat mode code automatically.  Thus if the flat mode
source is modified, the fdpic code is automatically updated.  This
meets the single code base requirement REQ2.

The asm code in src.fdpic should not be modified directly.  Modify the
code in src.orig instead.

Function Calls in FDPIC
-----------------------

During testing of the .so a problem was discovered with calls to
internal functions.  The .so linking process forces all calls to jump
to a PLT table to look up the address of the actual function being
called.  The PLT table is generated when the .so is linked.

For example:

$ bfin-uclinux-objump -d libg729.so

    6972:       ff e3 6c e2     CALL  2e4a <__init+0x37e>;

which calls this code:

    2e4a:       19 e5 a2 ff     P1=[P3+-376];
    2e4e:       1b e5 a3 ff     P3=[P3+-372];
    2e52:       51 00           JUMP  (P1);

However the PLT code assumes that several registers are reserved (P1
and P3).  The G729 asm does not reserve these registers, in fact they
are sometimes even used to pass function arguments.  To preserve these
registers a large amount of asm code would need to be modified and
debugged.

What we need is a way to use regular function calls (non-PLT) for
local functions.  That way we can use any register and argument
passing conventions we like internally.

Fortunately, in .so's, functions with local context use regular (non
PLT) linking.  For example this code in C:

  static void foo() {
  }

  void bar() {
    foo();
  }

would result in a .so that used a PLT to look up the address of bar(),
but regular linking (ie a direct function call) to foo().  However our
asm functions are in different modules, the technique above assumes
that the local functions are in the same module.

The trick is to use ld and objcopy to partially link all of the object
files, then convert the global function symbols to locals.  When the
.so is built, only a select few functions remain globals.  These are
the functions in the .so that are called by external programs.  Only
these functions are called via the PLT method.

The Makefile in src.fdpic handles this process.

Support for Multiple Codec Instances
------------------------------------

To support REQ3 the codec swaps state variables in and out of its
local storage at the start and end of each operation.  The local
storage is placed in L1 using linker options.  This introduces some
overhead for the swapping but minimises L1 usage.  It also means that
only one instance of the codec can run at any one time, requiring a
mutex to block access to the encode/decode functions by simultaneous
threads.

In practice this mutex has little effect on performance, as the codec
executes very quickly (300-400us worst case).  For example in a
typical 10ms processing frame, in most cases the codec will execute
immediately.  In the case where thread B is blocked while thread A
calls the codec, B will sleep until A has finished.  This is a
reasonable strategy as it minimises CPU cycles, thus meeting REQ4.

Note that the multi-tasking approach is designed for "one application,
multiple threads".  Multiple apps using the .so may work, but hasn't
been tested.  It will use an amount of L1 proportional to the number
of applications using the .so.

Notes and Further Work
----------------------

+ The "simulated GOT" code in src.simgot was used to incrementally
develop the fdpic conversion process.  It generates code that can
execute in flat mode, however the assembler is very close to the fdpic
code.  By converting one asm file at a time the fdpic conversion
process was debugged without having to convert and test the entire
code base in one "big bang".

+ The Perl script could be modified to generate more optimised code.
This will provide small performance gains in L1, but significant gains
if operating in external memory.

+ To best optimise the code further it is recommended that the asm be
rewritten to free P3/R0 (or any Rx register).  This is a significant
job.

+ After some experimentation it was decided to use one mutex for both
the encode and decode functions.  When two mutexes were tried, the
encoder was getting corrupted.  This suggests that there are state
variables shared between the encoder and decoder.

+ If during assembly you get something like:
  
  vad.asm:520: Error: pcrel too far BFD_RELOC_BFIN_10

  This means that the Perl script has introduced enough asm source
  code to make a relative jump too far away to assemble.  You need to
  modify the src.orig file to use an absolute jump.

+ The Perl script relies on global look ups to be in this form:

    I0.H = sharp;
    I0.L = sharp;

  This:

    I0.L = sharp;
    I0.H = sharp;

  and this:

    I0.H = sharp;
    (some other asm)
    I0.L = sharp;

  will cause the Perl script to stop with an error.  Most of the
  src.orig mods were to get the src into a from the Perl script could
  understand.  After each mod the flat code (g729ab_test) was run to
  ensure no errors had been introduced.
 
