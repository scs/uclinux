/*****************************************************************************
 *
 *  Project:      Dataprocessing Framework
 *
 * --------------------------------------------------------------------------
 *  Copyright (c) 2003 by Supercomputing Systems AG
 * --------------------------------------------------------------------------
 *
 *
 *  $History: $
 *
 *
 *****************************************************************************/

#ifndef _BAYER_LCV_H
#define _BAYER_LCV_H

enum {ROFFSET = 2, GOFFSET = 1, BOFFSET = 0};
enum Colors{ R = 0, G = 1, B = 2};
typedef enum Colors Color;

// BayerFilterfunction
unsigned char* DoBayerFiltering(unsigned char*, int, int, int);

// Determine position of first pixels in the input image
void DetFirstPos(int* nRx, int* nRy, int* nGx, int* nGy, int* nBx, int* nBy);

// Copy the pixels that will not be changed from input to the ouput
void CopyConstPix2Out(char* pInpData, char* pOutData, int nXSize, int nYSize, int nStartPixX, int nStartPixY, Color Col);

// Interpolate
void InterpGreen(char* pInpData, char* pOutData, int nXSize, int nYSize, int nStartPixX, int nStartPixY);
unsigned char InterpCurGreen(unsigned char* pInpData, int nCurIndx, int nXSize);
void InterpGreenBorder(unsigned char* pInpData, unsigned char* pOutData, int nXSize, int nYSize, int nStartPixX, int nStartPixY);
void InterpRedOrBlue(unsigned char* pInpData, unsigned char* pOutData, int nXSize, int nYSize, int nStartPixX, int nStartPixY, int isRed);
unsigned char InterpCurRedOrBlueDiag(unsigned char* pInpData, unsigned char* pOutData, int nCurIndx, int nXSize);
void InterpRedOrBlueBorder(unsigned char* pInpData, unsigned char* pOutData, int nXSize, int nYSize, int nStartPixX, int nStartPixY, int isRed);


#endif // _BAYER_LCV_H

