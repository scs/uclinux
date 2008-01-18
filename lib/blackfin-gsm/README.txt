README.txt for blackfin-gsm
David Rowe (www.rowetel.com)
9 June 2006

CONTENTS
--------

1. Usage
2. Optimisation 
3. Performance
4. Ideas for Further Work
5. How to Profile
6. Thanks

1. USAGE
--------

1/ To make:

  make

2/ To test:

  Download tgsm and a speech file like 

    http://www.speex.org/audio/samples/male.wav

  to your Blackfin hardware and type:

    root:/var/tmp> ./tgsm male.wav male.out
    TOTAL, 0
    SNR = 10.4591 dB enc 114 dec 39 k cycles/frame
    root:/var/tmp>

  When it runs it prints out the number of cycles it took to execute
  each 20ms encode and decode frame.

  You can then upload the output file (male.out) to your host and
  listen to it.  On my Linux box I use "play male.sw", the sw lets
  "play" recognise it as a 16-bit signed-word file.

2. OPTIMISATION
---------------

This is a Blackfin-optimised version of the GSM codec.  I spent
a day or so optimising the code, for example:

a) I wrote Blackfin versions of the macros in gsm/inc/private.h

b) Applied the profiling macros SAMCYCLES and worked out which parts
   of the code needed the most optimisation.

c) I looked at the assembler output of various functions and modified
   the C code for better output, such as using the hardware loop
   supported by gcc 4.1.  A lot of the original GSM code was written
   for older x86 compilers, and lots of compiler-specific mods were
   evident.  In many cases to speed up code I just went back to
   vanilla C and the Blackfin compiler did a better job!

e) By inspecting the assembler I found some important routines were
   making function calls inside their inner loops which is very
   inefficient.  These were modified to remove the function calls.

f) Use some assembler in the tightest, most cycle-hungry loops.

3. PERFORMANCE
--------------

Using gcc 4.1 and testing on a Blackfin STAMP BF533 board:

  encode: 114,000 cycles/frame: (114,000/0.02s) = 5.70 MIPs
  decode:  39,000 cycles/frame: ( 39,000/0.02s) = 1.95 MIPs

The initial number of cycles per encode was 274,000, decode 42,000.

4. IDEAS FOR FURTHER WORK 
-------------------------

My gut feel is it might be possible to reduce the total (encode plus
decode) cycles by perhaps another 30% with further optimisation.

a) The analysis and synthesis filter functions consume
   about 50,000 cycles per encode/decode cycle, they could be converted
   to assembler.  

b) The RPE algorithm (rpe.c) could be optimised. 

c) Blackfin internal memory might speed some operations, such as
   autocorrelation.

5. HOWTO PROFILE
----------------

I have written a set of macros (samcycles.h) to sample the Blackfin cycles
counter.  Here is an example on how to use them:

a) Patch code.c:

   patch -p0 < code_profile.patch

b) make, download tgsm and re-run on the target:

     root:/var/tmp> ./tgsm male.wav male.out
     start Gsm_Coder, 0
       Gsm_Preprocess, 5312
       Gsm_LPC_Analysis, 11406
       Gsm_Short_Term_Analysis_Filter, 23483
         Gsm_Long_Term_Predictor, 11525
         Gsm_RPE_Encoding, 8308
         Gsm_Long_Term_Predictor, 10947
         Gsm_RPE_Encoding, 5411
         Gsm_Long_Term_Predictor, 10701
         Gsm_RPE_Encoding, 5422
         Gsm_Long_Term_Predictor, 10696
         Gsm_RPE_Encoding, 5409
     end Gsm_Coder, 521
     TOTAL, 109141
     SNR = 10.4591 dB enc 115 dec 39 k cycles/frame
     root:/var/tmp>

c) To investigate further, just add more SAMCYCLES() macros.  Its a good
   idea to remove or disable the macros when you are finished, as they
   use a few thousand cycles:

   patch -R -p0 < code_profile.patch

6. THANKS
---------

To Jean-Marc Valin and the Speex project, I used some of their
assembler code (see COPYING.xiph for the copyright message related to
this code).
