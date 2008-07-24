The G.729 AB documentation is not clear in describing the output format
from the encoder and the input format to the decoder.  This document seeks to
clarify the documentation.

Please note that the encoder will issue as many as 82 16 bit words.  In some
cases it will issue as few as 2 16 bit words, however the customer should allocate
the full 82 16 bit word buffer to safely capture the encoder output.  If the 
output buffer is too short, then it is likely that the encoder will overwrite
the output buffer causing memory corruption.

Please note that the decoder input is an identical format to the encoder output.

It is critical that the customer realise that the number of output words will vary
depending on what is happening with the signal.  When there is active speech then there
will be 80 significant bits of output data.  When there is no active speech there could be
16 or 0 bits of data output depending on what is happening inside the encoder.

The encoder output is a regular format.  It always has the sync word as the first output (0x6b21),
followed by a count, which is the number of significant bits.

In packed mode the bits are packed into 16 bit words with all 16 bits in use.
In unpacked mode the bits are placed one bit per word, where a 1 is represented as 0x81 and a 0 is 0x7f.

Here is a diagram of the data format:
+---------+---------+--------------+--------------+-----------------------------+
| 0x6b21  |  Count  | Data word[0] | Data word[1] | ..... up to Data word[n-1]  |
+---------+---------+--------------+--------------+-----------------------------+
The relationship between count and 'n' is as follows
- Packed mode: n=count/16
- Unpacked mode: n=count
Note that it is quite valid for count to equal zero.  In this case there is no data
to be transmitted to the decoder over the transmission channel.

On the decoder input, the same format must be used.  So the sync word must be followed by the
number of input bit count.  Then the data must be presented in either packed or unpacked format.
The decoder input must be setup so the correct count is placed in the input array.  If no data was 
transmitted, then the decoder must still be called, with a 'count' of zero.  The decoder will then
generate fill in noise.

In most normal systems the sync word and the count will be stripped off the encoder output
buffer and will not be transmitted over the transmission channel.
The count will be used to determine what is transmitted to the decoder.  If the 
count is 80, then the full 80 bits should be transmitted.  If the count is 16, then only
16 bits need be transmitted.  If the count is 0, then no data needs to be transmitted.

On the decoder side, the user application code needs to set up the input buffer starting
with a sync word.  Then the count needs to be set.  If a packet with 80 bits is received,
then the user application should set the count to 80.  With a packet size of 16 bits the
count should be 16.  If no data is received the count should be zero.  After the count
is set then the data should be placed into the decoder input buffer in either packed
or unpacked format, depending on the preference set via the API.
