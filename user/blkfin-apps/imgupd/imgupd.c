/*
 * Copyright (c) 2007 Supercomputing Systems AG
 * All rights reserved.
 *
 * Author: Markus Berner
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEMP_FILE_LOCATION "/tmp/"
#define U_BOOT_PARTITION "/dev/uboot"
#define LINUX_PARTITION "/dev/linux"
#define CALIBRATION_PARTITION "/dev/calib"

#define XSTR(x) #x
#define STR(x) XSTR(x)
int main(int argc, char** argv)
{
  FILE * pF;
  void * pBuf;
  char sTemp[1024];
  char * sImgName;
  char sTempFileLocation[256];
  char *sServerIp;
  int bLocalFile = 0;


  int ret = -1;
  unsigned int * pWrd;
  
  if(argc != 2 && argc != 3)
  {
      printf("Usage: %s <image file> [<ip>]\n", argv[0]);
      return -1;
  }
  
  sImgName = argv[1];
  if(argc == 3)
  {
    /* If the IP address is supplied as an argument, use this one. */
    sServerIp = argv[2];
  } else {
    /* Check if the file already exists locally. If so, use it instead of TFTPing it
       from remote.*/
    if(access(sImgName, R_OK) == 0)
      {
	printf("Using local copy \"%s\".\n", sImgName);
	bLocalFile = 1;
	sTempFileLocation[0] = '\0';
      }
    /* Otherwise get the server ip from U-Boot environment variables. */
    sServerIp = "`fw_printenv | grep \"serverip=\" | sed -e s/serverip=//g`";
  }

  if(!bLocalFile)
    {
      strcpy(sTempFileLocation, TEMP_FILE_LOCATION);

      printf("Transferring %s over tftp...\n", sImgName);
      sprintf(sTemp, "tftp %s -g -l %s%s -r %s\n", sServerIp, sTempFileLocation, sImgName, sImgName);
      printf("%s\n", sTemp);
      ret = system(sTemp);
      if(ret != 0)
	{
	  printf("Transfer failed! Aborting...\n");
	  return -1;
	}
    }

  printf("Analyzing file header of \"%s\".\n", sImgName);
  sprintf(sTemp, "%s%s", sTempFileLocation, sImgName);
  pF = fopen(sTemp, "rb");
  if(!pF)
  {
      printf("Unable to open %s!\n", sImgName);
      return -1;
  }
  
  pBuf = malloc(1024);
  
  fread(pBuf, 4, 1, pF);
  pWrd = (unsigned int*)pBuf;
  
  switch(*pWrd)
    {
    case 0xFF800020:
    case 0xFF800040:
    case 0xFF800060:
    case 0xFFA00000:
      printf("Magic word of U-Boot image found\n");
      printf("Copying to %s...\n", U_BOOT_PARTITION);
      sprintf(sTemp, "cp %s%s %s\n", TEMP_FILE_LOCATION, sImgName, U_BOOT_PARTITION); 
      ret = system(sTemp);
      goto cleanup;
      break;
    case 0x56190527:
      printf("Magic word of OS image found!\n");
      printf("Copying to %s...\n", LINUX_PARTITION);
      sprintf(sTemp, "cp %s%s %s\n", TEMP_FILE_LOCATION, sImgName, LINUX_PARTITION); 
      ret = system(sTemp);
      goto cleanup;
      break;
    case 0x012345678:
      printf("Magic word of Sensor Calibration image found!\n");
      printf("Copying to %s...\n", CALIBRATION_PARTITION);
      sprintf(sTemp, "cp %s%s %s\n", TEMP_FILE_LOCATION, sImgName, CALIBRATION_PARTITION);
      ret = system(sTemp);
      goto cleanup;
    default:
      printf("Image not recognized!\n");
      goto cleanup;
      break;
   }
 cleanup:
  if(!bLocalFile)
    {
      sprintf(sTemp, "rm %s%s\n", sTempFileLocation, sImgName);
      system(sTemp);
    }
   return ret;
}
