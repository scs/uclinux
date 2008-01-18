

/*--------------------------------------------------------------------------*
 *       Codec constant parameters (coder, decoder, and postfilter)         *
 *--------------------------------------------------------------------------*/

#define  L_TOTAL      240     /* Total size of speech buffer.               */
#define  L_WINDOW     240     /* Window size in LP analysis.                */
#define  L_NEXT       40      /* Lookahead in LP analysis.                  */
#define  L_FRAME      80      /* Frame size.                                */
#define  L_SUBFR      40      /* Subframe size.                             */
//#define  M            10      /* Order of LP filter.                        */
//#define  MP1          (M+1)   /* Order of LP filter + 1                     */
#define  PIT_MIN      20      /* Minimum pitch lag.                         */
#define  PIT_MAX      143     /* Maximum pitch lag.                         */
#define  L_INTERPOL   (10+1)  /* Length of filter for interpolation.        */
#define  GAMMA1       24576   /* Bandwitdh factor = 0.75   in Q15           */

#define  PRM_SIZE     11      /* Size of vector of analysis parameters.     */
#define  SERIAL_SIZE  (80+2)  /* bfi+ number of speech bits                 */

#define SHARPMAX  13017   /* Maximum value of pitch sharpening     0.8  Q14 */
#define SHARPMIN  3277    /* Minimum value of pitch sharpening     0.2  Q14 */


#define MAX_NO1 0xffff
#define MAX_NO2 0x7fff 
#define AUTOCORR_CONST1 0x8000
#define LEVINSON_CONST1 0x0002
#define LEVINSON_CONST2 32750
/*********8Chebps routine**************/
#define CHEBPS_CNT 5
#define CHEBPS_CONST1 0x0100  //256
#define CHEBPS_CONST2 0x0200  //512
#define CHEBPS_CONST3 4096  
#define CHEBPS_CONST4 -32768
#define LSPLSF_CONST1 63

#define VAD_CONST1 9864
#define VAD_CONST2 4875
#define MAX_16 0x7fff

/*****************Pitch_ol_fast************************/
#define MIN_32 0x8000

#define GPITCH_CONST1 19661
#define CORH_CONST1 32000

