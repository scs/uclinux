
/***********************************************
 * cfa2bgr();
 *
 * Convert 8bpp RAW image data from CMOS Sensor 
 * to 24bpp BGR image
 *
 * Input: point to RAW image buffer
 *        image width
 *        image height
 *
 * Output: pointer to new BGR image buffer
 *
 **********************************************/

#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>

#include <assert.h>
#include "bayer-lcv.h"

#define INTDIVIDEBY2ROUND(x) ((x + 1) / 2)
#define INTDIVIDEBY3ROUND(x) ((x + 1) / 3)
#define INTDIVIDEBY4ROUND(x) ((x + 2) / 4)
#define INTDIVIDEBY8ROUND(x) ((x + 4) / 8)
#define SATURATE2CHAR(x) (x < 0 ? 0 : (x > 255 ? 255 : x))
#define ISODD(x)         (x & 0x1)


// Set info on Bayer Pattern, i.e. where to find which color
Color m_FirstPixColor = B;
Color m_SecondPixColor = G;

unsigned char * cfa2bgr_AllocMem(int size)
{
  /* Allocate memory for the raw image and BMP Header */
  unsigned char *buffer = (unsigned char *)malloc(size);
  return buffer;
}



unsigned char* cfa2bgr_DoBayerFiltering(unsigned char* raw_buf, int header_size, int width, int height)
/* Used algorithm:
  Linear Interpolation with Laplacian second-order correction terms I.
  See http://scien.stanford.edu/class/psych221/projects/99/tingchen/main.htm

  The output input has the following format: BGR
*/
{
       int nRx, nRy, nGx, nGy, nBx, nBy;

       unsigned char* pInputImage = raw_buf;
       unsigned char* pOutImageHeader = cfa2bgr_AllocMem(3*width*height + header_size);
       unsigned char* pOutImage   = (unsigned char*)(pOutImageHeader + header_size);
       int   nXSize      = width;
       int   nYSize      = height;
       
       // Only for better debuging
       // memset(pOutImage, 0, m_outputimage->getImageSizeInByte());

       cfa2bgr_DetFirstPos(&nRx, &nRy, &nGx, &nGy, &nBx, &nBy);

       // Copy the pixel of input image that can be used without
       // interpolation to the output pixels
       //--------------------------------------------------------

       cfa2bgr_CopyConstPix2Out(pInputImage, pOutImage, nXSize, nYSize, nRx, nRy, R);
       cfa2bgr_CopyConstPix2Out(pInputImage, pOutImage, nXSize, nYSize, nGx, nGy, G);
       cfa2bgr_CopyConstPix2Out(pInputImage, pOutImage, nXSize, nYSize, nBx, nBy, B);

       // Interpolate
       //------------

       cfa2bgr_InterpGreen(pInputImage, pOutImage, nXSize, nYSize, nGx, nGy);
       cfa2bgr_InterpRedOrBlue(pInputImage, pOutImage, nXSize, nYSize, nRx, nRy, 1);
       cfa2bgr_InterpRedOrBlue(pInputImage, pOutImage, nXSize, nYSize, nBx, nBy, 0);

       return pOutImageHeader;
}

void cfa2bgr_DetFirstPos(int* nRx, int* nRy, int* nGx, int* nGy, int* nBx, int* nBy)
{
       if (m_FirstPixColor == R)       // RGRG
       {                               // GBGB
               *nRx = 0; *nRy = 0;
               *nGx = 1; *nGy = 0;
               *nBx = 1; *nBy = 1;
       }
       else if (m_FirstPixColor == B)  // BGBG
       {                               // GRGR
               *nRx = 1; *nRy = 1;
               *nGx = 1; *nGy = 0;
               *nBx = 0; *nBy = 0;
       }
       else
       {
               if (m_SecondPixColor == R)  // GRGR
               {                           // BGBG
                       *nRx = 1; *nRy = 0;
                       *nGx = 0; *nGy = 0;
                       *nBx = 0; *nBy = 1;
               }
               else if (m_SecondPixColor == B)  // GBGB
               {                                // RGRG
                       *nRx = 0; *nRy = 1;
                       *nGx = 0; *nGy = 0;
                       *nBx = 1; *nBy = 0;
               }
       }
}

void cfa2bgr_CopyConstPix2Out(unsigned char* pInpData, unsigned char* pOutData, int nXSize, int nYSize, int nStartPixX, int nStartPixY, Color Col)
{
       int i, j, k;
       int nCurLineInp, CurIndx;
       int nColOffset, nRuns;

       int StartPixX[2];
       int StartPixY[2];
       StartPixX[0] = nStartPixX;
       StartPixY[0] = nStartPixY;

       // Prepare values for different colors
       if (Col == G)
       {
               nRuns        = 2;
               StartPixX[1] = nStartPixX == 0 ? 1 : 0;    // Start pos. for 2. run
               StartPixY[1] = 1;
               nColOffset   = GOFFSET;
       }
       else
       {
               nRuns = 1;
               if (Col == B)
                       nColOffset = BOFFSET;
               else
                       nColOffset = ROFFSET;
       }

       // Copy pixels that are not interpolated
       for (k = 0; k < nRuns; k++)
       {
               for (i = StartPixY[k]; i < nYSize; i += 2)
               {
                       nCurLineInp = i * nXSize;
                       for (j = StartPixX[k]; j < nXSize; j +=2)
                       {
                               CurIndx = nCurLineInp + j;
                               pOutData[3 * CurIndx + nColOffset] = pInpData[CurIndx];
                       }
               }
       }
}


unsigned char cfa2bgr_InterpCurGreen(unsigned char *pInpData, int nCurIndx, int nXSize)
{
       // Laplace horizontal and vertical
       int nLapH, nLapV;
       int nDeltaH, nDeltaV;
       int nTmp, nOutVal;

       int GW = pInpData[nCurIndx-1];        // Green Color
       int GE = pInpData[nCurIndx+1];        // Green Color
       int GN = pInpData[nCurIndx-nXSize];   // Green Color
       int GS = pInpData[nCurIndx+nXSize];   // Green Color

       nTmp  = 2 * pInpData[nCurIndx];
       nLapH = nTmp - pInpData[nCurIndx - 2]        - pInpData[nCurIndx + 2];        // Other colors
       nLapV = nTmp - pInpData[nCurIndx - 2*nXSize] - pInpData[nCurIndx + 2*nXSize]; // Other colors

       nDeltaH = abs(GW - GE) + abs(nLapH);
       nDeltaV = abs(GN - GS) + abs(nLapV);

       if (nDeltaH < nDeltaV)
       {
               // nOutVal = (GW + GE) / 2 + nLapH / 4;
               nOutVal = INTDIVIDEBY4ROUND(2 * (GW + GE) + nLapH);
       }
       else if (nDeltaH > nDeltaV)
       {
               // nOutVal = (GN + GS) / 2 + nLapV / 4;
               nOutVal = INTDIVIDEBY4ROUND(2 * (GN + GS) + nLapV);
       }
       else
       {
               // nOutVal = (GN + GE + GS + GW) / 4 + (nLapV + nLapH) / 8;
               nOutVal = INTDIVIDEBY8ROUND(2 * (GN + GE + GS + GW) + (nLapV + nLapH));
       }

       return SATURATE2CHAR(nOutVal);
}

void cfa2bgr_InterpGreen(unsigned char* pInpData, unsigned char* pOutData, int nXSize, int nYSize, int nStartPixX, int nStartPixY)
{
       assert(nStartPixY == 0);

       int i, j;
       int nCurLineInp, nCurIndx;                           //     X
                                                        //     G
       int nStartX0 = nStartPixX == 0 ? 3 : 2;              // X G X G X
       int nStartX1 = nStartPixX == 0 ? 2 : 3;              //     G
                                                        //     X
       for (i = 2; i < nYSize-2; i += 2)
       {
               nCurLineInp = i * nXSize;
               for (j = nStartX0; j < nXSize-2; j +=2)
               {
                       nCurIndx = nCurLineInp + j;
		       pOutData[3 * nCurIndx + GOFFSET] = cfa2bgr_InterpCurGreen(pInpData, nCurIndx, nXSize);
               }
               nCurLineInp = (i+1) * nXSize;
               for (j = nStartX1; j < nXSize-2; j +=2)
               {
                       nCurIndx = nCurLineInp + j;
		       pOutData[3 * nCurIndx + GOFFSET] = cfa2bgr_InterpCurGreen(pInpData, nCurIndx, nXSize);
               }
       }

       // Border must handled separate.
       cfa2bgr_InterpGreenBorder(pInpData, pOutData, nXSize, nYSize, nStartPixX, nStartPixY);
}


void cfa2bgr_InterpGreenBorder(unsigned char* pInpData, unsigned char* pOutData, int nXSize, int nYSize, int nStartPixX, int nStartPixY)
/* Only linear interpolation
*/
{
       int  i;
       int  nCurVal, nCurIndx;
       int  nStartX, nStartY;
       int isOddXSize = ISODD(nXSize);
       int isOddYSize = ISODD(nYSize);

       // First Line
       for (i = nStartPixX+1; i < nXSize-1; i +=2)
       {
               nCurVal = pInpData[i-1] + pInpData[i+1] + pInpData[i+nXSize];
               pOutData[3 * i + GOFFSET] = INTDIVIDEBY3ROUND(nCurVal);
       }

       // Second Line
       nStartX = nStartPixX == 0 ? 2 : 1;
       for (i = nStartX; i < nXSize-1; i +=2)
       {
               nCurIndx = nXSize + i;
               nCurVal  = pInpData[nCurIndx-1] + pInpData[nCurIndx+1] + pInpData[nCurIndx-nXSize] + pInpData[nCurIndx+nXSize];
               pOutData[3 * nCurIndx + GOFFSET] = INTDIVIDEBY4ROUND(nCurVal);
       }

       // First Column
       nStartY = nStartPixX == 0 ? 1: 2;
       for (i = nStartY; i < nYSize-1; i +=2)
       {
               nCurIndx = i * nXSize;
               nCurVal  = pInpData[nCurIndx-nXSize] + pInpData[nCurIndx+nXSize] + pInpData[nCurIndx+1];
               pOutData[3 * nCurIndx + GOFFSET] = INTDIVIDEBY3ROUND(nCurVal);
       }

       // Second Column
       nStartY = nStartPixX == 0 ? 2: 1;
       for (i = nStartY; i < nYSize-1; i +=2)
       {
               nCurIndx = i * nXSize + 1;
               nCurVal  = pInpData[nCurIndx-nXSize] + pInpData[nCurIndx+nXSize] + pInpData[nCurIndx-1] + pInpData[nCurIndx+1];
               pOutData[3 * nCurIndx + GOFFSET] = INTDIVIDEBY4ROUND(nCurVal);
       }

       // Top left corner
       if (nStartPixX > 0)
       {
               nCurVal = pInpData[1] + pInpData[nXSize];
               pOutData[0 + GOFFSET] = INTDIVIDEBY2ROUND(nCurVal);
       }

       // Last Line
       if (   nStartPixX == 0 && isOddYSize
               || nStartPixX == 1 && !isOddYSize)
               nStartX = 1;
       else
               nStartX = 2;
       for (i = nStartX; i < nXSize-1; i +=2)
       {
               nCurIndx = nXSize * (nYSize - 1) + i;
               nCurVal  = pInpData[nCurIndx-1] + pInpData[nCurIndx+1] + pInpData[nCurIndx-nXSize];
               pOutData[3 * nCurIndx + GOFFSET] = INTDIVIDEBY3ROUND(nCurVal);
       }

       // Second last Line
       if (   nStartPixX == 0 && isOddYSize
               || nStartPixX == 1 && !isOddYSize)
               nStartX = 2;
       else
               nStartX = 1;
       for (i = nStartX; i < nXSize-1; i +=2)
       {
               nCurIndx = nXSize * (nYSize - 2) + i;
               nCurVal  = pInpData[nCurIndx-1] + pInpData[nCurIndx+1] + pInpData[nCurIndx-nXSize] + pInpData[nCurIndx+nXSize];
               pOutData[3 * nCurIndx + GOFFSET] = INTDIVIDEBY4ROUND(nCurVal);
       }

       // Bottom left corner
       if (   nStartPixX == 1 && isOddYSize
               || nStartPixX == 0 && !isOddYSize)
       {
               nCurVal = pInpData[(nYSize-2) * nXSize] + pInpData[(nYSize-1) * nXSize + 1];
               pOutData[3 * nXSize * (nYSize - 1) + GOFFSET] = INTDIVIDEBY2ROUND(nCurVal);
       }

       // Last Column
       if (   nStartPixX == 0 && isOddXSize
               || nStartPixX == 1 && !isOddXSize)
               nStartY = 1;
       else
               nStartY = 2;
       for (i = nStartY; i < nYSize-1; i +=2)
       {
               nCurIndx = i * nXSize + nXSize - 1;
               nCurVal  = pInpData[nCurIndx-nXSize] + pInpData[nCurIndx+nXSize] + pInpData[nCurIndx-1];
               pOutData[3 * nCurIndx + GOFFSET] = INTDIVIDEBY3ROUND(nCurVal);
       }

       // Second last Column
       if (   nStartPixX == 0 && isOddXSize
               || nStartPixX == 1 && !isOddXSize)
               nStartY = 2;
       else
               nStartY = 1;
       for (i = nStartY; i < nYSize-1; i +=2)
       {
               nCurIndx = i * nXSize + nXSize - 2;
               nCurVal  = pInpData[nCurIndx-nXSize] + pInpData[nCurIndx+nXSize] + pInpData[nCurIndx-1] + pInpData[nCurIndx+1];
               pOutData[3 * nCurIndx + GOFFSET] = INTDIVIDEBY4ROUND(nCurVal);
       }

       // Top right pixel
       if (   nStartPixX == 0 && !isOddXSize
               || nStartPixY == 1 && isOddXSize)
       {
               nCurVal = pInpData[nXSize-2] + pInpData[2 * nXSize - 1];
               pOutData[3 * (nXSize - 1) + GOFFSET] = INTDIVIDEBY2ROUND(nCurVal);
       }

       // Bottom right pixel
       if (   nStartPixX == 0 && (isOddXSize && !isOddYSize || isOddYSize  && !isOddXSize)
               || nStartPixX == 1 && (isOddXSize && isOddYSize  || !isOddYSize && !isOddXSize))
       {
               nCurVal = pInpData[nYSize * nXSize - 2] + pInpData[(nYSize - 1) * nXSize - 1];
               pOutData[3 * (nXSize * nYSize - 1) + GOFFSET] = INTDIVIDEBY2ROUND(nCurVal);
       }
}

unsigned char cfa2bgr_InterpCurRedOrBlueDiag(unsigned char* pInpData, unsigned char* pOutData, int nCurIndx, int nXSize)
{
       // Laplace horizontal and vertical
       int nLapN, nLapP;
       int nDeltaN, nDeltaP;
       int nTmp, nOutVal;

       int CNW = pInpData[nCurIndx-1-nXSize];   // Current Color
       int CNE = pInpData[nCurIndx+1-nXSize];   // Current Color
       int CSE = pInpData[nCurIndx+1+nXSize];   // Current Color
       int CSW = pInpData[nCurIndx-1+nXSize];   // Current Color

       nTmp  = 2 * pOutData[3 * nCurIndx + GOFFSET];
       nLapN = nTmp - pOutData[3 * (nCurIndx-1-nXSize) + GOFFSET] - pOutData[3 * (nCurIndx+1+nXSize) + GOFFSET]; // Green color
       nLapP = nTmp - pOutData[3 * (nCurIndx+1-nXSize) + GOFFSET] - pOutData[3 * (nCurIndx-1+nXSize) + GOFFSET]; // Green color

       nDeltaN = abs(CNW - CSE) + abs(nLapN);
       nDeltaP = abs(CNE - CSW) + abs(nLapP);

       if (nDeltaN < nDeltaP)
       {
               // nOutVal = (CNW + CSE)/2 + nLapN/2;
               nOutVal = INTDIVIDEBY2ROUND(CNW + CSE + nLapN);
       }
       else if (nDeltaN > nDeltaP)
       {
               // nOutVal = (CNE + CSW)/2 + nLapP/2;
               nOutVal = INTDIVIDEBY2ROUND(CNE + CSW + nLapP);
       }
       else
       {
               // nOutVal = (CNW + CNE + CSE + CSW) / 4 + (nLapV + nLapH) / 4;
               nOutVal = INTDIVIDEBY4ROUND(CNW + CNE + CSE + CSW + nLapN + nLapP);
       }

       return SATURATE2CHAR(nOutVal);

}


void cfa2bgr_InterpRedOrBlue(unsigned char* pInpData, unsigned char* pOutData, int nXSize, int nYSize, int nStartPixX, int nStartPixY, int isRed)
{
       int i, j;
       int nCurLineInp, nCurIndx;
       int nCurVal;
       int nColOffset = isRed ? ROFFSET : BOFFSET;
       int nStartX0, nStartX1, nStartX2;
       int nStartY0, nStartY1, nStartY2;

       if (nStartPixX == 0)
       {
               nStartX0 = 0;
               nStartX1 = 1;
               nStartX2 = 1;
       }
       else
       {
               nStartX0 = 1;
               nStartX1 = 2;
               nStartX2 = 2;
       }

       if (nStartPixY == 0)
       {
               nStartY0 = 1;
               nStartY1 = 0;
               nStartY2 = 1;
       }
       else
       {
               nStartY0 = 2;
               nStartY1 = 1;
               nStartY2 = 2;
       }

       for (i = nStartY0; i < nYSize-1; i += 2)        //  R      B
       {                                               //  G  or  G
               nCurLineInp = i * nXSize;                   //  R      B
               for (j = nStartX0; j < nXSize; j += 2)
               {
                       nCurIndx =  nCurLineInp + j;
                       nCurVal  =  2 * (pInpData[nCurIndx-nXSize] + pInpData[nCurIndx+nXSize]);                                                     // Current Color
                       nCurVal  += 2 * pInpData[nCurIndx] - pOutData[3 * (nCurIndx-nXSize) + GOFFSET] - pOutData[3 * (nCurIndx+nXSize) + GOFFSET];  // Green Color
                       nCurVal  = INTDIVIDEBY4ROUND(nCurVal);
                       pOutData[3 * nCurIndx + nColOffset] = SATURATE2CHAR(nCurVal);
               }
       }

       for (i = nStartY1; i < nYSize; i +=2)         // R G R   or    B G B
       {
               nCurLineInp = i * nXSize;
               for (j = nStartX1; j < nXSize-1; j += 2)
               {
                       nCurIndx =  nCurLineInp + j;
                       nCurVal  =  2 * (pInpData[nCurIndx-1] + pInpData[nCurIndx+1]);                                         // Current Color
                       nCurVal  += 2 * pInpData[nCurIndx] - pOutData[3 * (nCurIndx-1) + GOFFSET] - pOutData[3 * (nCurIndx+1) + GOFFSET];  // Green Color
                       nCurVal  = INTDIVIDEBY4ROUND(nCurVal);
                       pOutData[3 * nCurIndx + nColOffset] = SATURATE2CHAR(nCurVal);
               }
       }

       for (i = nStartY2; i < nYSize-1; i +=2)         // R G R      B G B
       {                                               // G B G  or  G R G
               nCurLineInp = i * nXSize;                   // R G R      B G B
               for (j = nStartX2; j < nXSize-1; j += 2)
               {
                       nCurIndx =  nCurLineInp + j;
                       pOutData[3 * nCurIndx + nColOffset] = cfa2bgr_InterpCurRedOrBlueDiag(pInpData, pOutData, nCurIndx, nXSize);
               }
       }

       // Border must handled separate
       cfa2bgr_InterpRedOrBlueBorder(pInpData, pOutData, nXSize, nYSize, nStartPixX, nStartPixY, isRed);
}


void cfa2bgr_InterpRedOrBlueBorder(unsigned char* pInpData, unsigned char* pOutData, int nXSize, int nYSize, int nStartPixX, int nStartPixY, int isRed)
/* Copy values from the neighbour line or column in the output image.
*/
{
       int  nColOffset = isRed ? ROFFSET : BOFFSET;
       int isOddXSize = ISODD(nXSize);
       int isOddYSize = ISODD(nYSize);

       int i, nCurIndx;

       // Top Border
       if (nStartPixY == 1)
       {
               for (i = nStartPixX; i < nXSize; i++)
               {
                       pOutData[3 * i + nColOffset] = pOutData[3 * (i + nXSize) + nColOffset];
               }
       }

       // Left Border
       if (nStartPixX == 1)
       {
               for (i = nStartPixY; i < nYSize; i++)
               {
                       pOutData[3 * i * nXSize + nColOffset] = pOutData[3 * (i * nXSize + 1) + nColOffset];
               }
       }

       // Top left corner
       pOutData[nColOffset] = pInpData[nStartPixY * nXSize + nStartPixX];

       // Bottom Border
       if (nStartPixY == 0 && !isOddYSize || nStartPixY == 1 && isOddYSize)
       {
               nCurIndx = (nYSize - 1) * nXSize;
               for (i = nStartPixX; i < nXSize; i++)
               {
                       pOutData[3 * (nCurIndx + i) + nColOffset] = pOutData[3 * (nCurIndx - nXSize + i) + nColOffset];
               }

       }

       // Bottom left corner
       if (nStartPixY == 0 && isOddYSize || nStartPixY == 1 && !isOddYSize)
               // Take from last line
               pOutData[3 * (nYSize-1) * nXSize + nColOffset] = pInpData[(nYSize - 1) * nXSize + nStartPixX];
       else
               // Take from second last line
               pOutData[3 * (nYSize-1) * nXSize + nColOffset] = pInpData[(nYSize - 2) * nXSize + nStartPixX];


       // Right Border
       if (nStartPixX == 0 && !isOddXSize || nStartPixX == 1 && isOddXSize)
       {
               nCurIndx = nXSize - 1;
               for (i = nStartPixY; i < nYSize; i++)
               {
                       pOutData[3 * (i * nXSize + nCurIndx) + nColOffset] = pOutData[3 * (i * nXSize + nCurIndx - 1) + nColOffset];
               }
       }

       // Top right corner
       if (nStartPixX == 0 && isOddXSize || nStartPixX == 1 && !isOddXSize)
               // Take from last column
               pOutData[3 * (nXSize - 1) + nColOffset] = pInpData[nStartPixY * nXSize + nXSize - 1];
       else
               // Take from second last column
               pOutData[3 * (nXSize - 1) + nColOffset] = pInpData[nStartPixY * nXSize + nXSize - 2];

       // Bottom right corner
       if (nStartPixY == 0 && isOddYSize || nStartPixY == 1 && !isOddYSize)
       {
               // Take from last line
               if (nStartPixX == 0 && isOddXSize || nStartPixX == 1 && !isOddXSize)
                       // Take from last column
                       pOutData[3 * (nXSize * nYSize - 1) + nColOffset] = pInpData[(nYSize - 1) * nXSize + nXSize - 1];
               else
                       // Take from second last column
                       pOutData[3 * (nXSize * nYSize - 1) + nColOffset] = pInpData[(nYSize - 1) * nXSize + nXSize - 2];
       }
       else
       {
               // Take from second last line
               if (nStartPixX == 0 && isOddXSize || nStartPixX == 1 && !isOddXSize)
                       // Take from last column
                       pOutData[3 * (nXSize * nYSize - 1) + nColOffset] = pInpData[(nYSize - 2) * nXSize + nXSize - 1];
               else
                       // Take from second last column
                       pOutData[3 * (nXSize * nYSize - 1) + nColOffset] = pInpData[(nYSize - 2) * nXSize + nXSize - 2];
       }
}

// end of file

