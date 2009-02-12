Due to limitation of msh, the original xeno-test scrip cannot work.
The script has to be seperated into several pieces.

Here is result on BF537-STAMP board, using load (dd if=/dev/zero of=/dev/null count=2M)

1.  latency -t0 -sh -T 120
No load:
HSH|--param|--samples-|--average--|---stddev--
HSS|    min|       119|      0.000|      0.000
HSS|    avg|   1199957|      1.445|      2.267
HSS|    max|       119|     22.605|      2.467

With load:
HSH|--param|--samples-|--average--|---stddev--
HSS|    min|       120|      0.508|      0.608
HSS|    avg|   1202073|      2.923|      2.571
HSS|    max|       120|     20.092|      3.133

2.  latency -t1 -sh -T 120
No load:
HSH|--param|--samples-|--average--|---stddev--
HSS|    min|       120|      0.658|      0.476
HSS|    avg|   1200264|      1.351|      1.608
HSS|    max|       120|     19.292|      2.763

With load:
HSH|--param|--samples-|--average--|---stddev--
HSS|    min|       120|      0.467|      0.501
HSS|    avg|   1202179|      2.851|      2.073
HSS|    max|       120|     20.058|      3.738

3.  switchtest -T 120
No load:
TD|        2247|       95967
RTD|        2250|       98217
RTD|        2244|      100461
RTD|        2175|      102636

With load:
RTD|        2250|       96066
RTD|        2250|       98316
RTD|        2244|      100560
RTD|        2247|      102807

4.  switchbench -h
No load:
RTH|     lat min|     lat avg|     lat max|        lost
RTD|      13.060|      15.092|      23.864|           0
HSS|     99996|     14.279|      1.267

With load:
RTH|     lat min|     lat avg|     lat max|        lost
RTD|      13.170|      18.256|      27.654|           0
HSS|     99996|     17.563|      2.108

5. cyclictest -p 10 -n -l 1000
No load:
T: 0 (  512) P:10 I:    1000 C:     955 Min:       0 Act:      18 Avg:       9 Max:      36

With load:
T: 0 (  541) P:10 I:    1000 C:     999 Min:       5 Act:      27 Avg:      15 Max:      50

