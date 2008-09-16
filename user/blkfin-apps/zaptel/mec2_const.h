/* 
   Important constants for tuning mec2 echo can
 */
#ifndef _MEC2_CONST_H
#define _MEC2_CONST_H


/* Convergence speed -- higher means slower */
#define DEFAULT_BETA1_I 2048
#define DEFAULT_SIGMA_LY_I 7
#define DEFAULT_SIGMA_LU_I 7
#define DEFAULT_ALPHA_ST_I 5
#define DEFAULT_ALPHA_YT_I 5
#define DEFAULT_CUTOFF_I 128
#define DEFAULT_HANGT 600
#define DEFAULT_SUPPR_I 16
#define MIN_UPDATE_THRESH_I 4096
#define DEFAULT_M 16
#define SUPPR_FLOOR -64
#define SUPPR_CEIL -24
#define RES_SUPR_FACTOR -20
#define AGGRESSIVE_HCNTR 160	/* 20ms */

#endif /* _MEC2_CONST_H */

