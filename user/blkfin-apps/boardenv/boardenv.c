/*
 * Copyright (c) 2007 Supercomputing Systems AG
 * All rights reserved.
 * 
 * Used to print/store board specific information. Data is hold in /env_board
 *
 * Author: Samuel Zahnd
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENV_BOARD_PARTITION "/env_board"
#define MAC_LEN 6

struct DATA_STORAGE {
	// optionaly: secure with crc32 or md5sum	
	unsigned char mac[MAC_LEN];
	// optionaly: Add more properties like serial number string  
};

int main(int argc, char** argv)
{
  FILE * pF;
  void * pBuf;
  char * pStrMacAddr;
  char * pStrArg;
  unsigned int tmpMac[MAC_LEN];
  struct DATA_STORAGE cfg;
  unsigned int i;
  unsigned char tmp;
  
  int ret = -1;
  
  if(argc == 2)
  {  
	pStrArg = argv[1];
	
	if( strcmp( pStrArg, "-h") == 0)
	{ 
       	printf("Print usage: %s \n" \
      		 "Store usage: %s <MAC Addr>\n", argv[0], argv[0]);
 		return -1;
	}
  }

  if(argc == 1)
  {
	/* print current configuration data */

	pBuf = malloc(1024);
	pF = fopen(ENV_BOARD_PARTITION, "rb");
	
	if(pF == NULL)
	{
		printf("%s not found!\n", ENV_BOARD_PARTITION);
		return -1;
	}	
	 	
  	for(i=0; i<MAC_LEN; i++)
  	{
  		fread(pBuf, sizeof(unsigned char), 1, pF);
  		tmp = *(unsigned char*)pBuf;
  		cfg.mac[i] = (unsigned int) tmp;
  	}	

	printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", cfg.mac[0], cfg.mac[1], cfg.mac[2], cfg.mac[3], cfg.mac[4], cfg.mac[5]);
	fclose(pF);
	ret = 0;
  } 
  else 
  {
  	/* store new configuration data */	  
  	pStrMacAddr = argv[1];  	
  	
  	sscanf(pStrMacAddr, "%2x:%2x:%2x:%2x:%2x:%2x", &tmpMac[0], &tmpMac[1], &tmpMac[2], &tmpMac[3], &tmpMac[4], &tmpMac[5]);
  	
	pF = fopen(ENV_BOARD_PARTITION, "wb");	
  	
  	for(i=0; i<MAC_LEN; i++)
  	{
  		cfg.mac[i] = (unsigned char)tmpMac[i];
  		fwrite(&cfg.mac[i], sizeof(unsigned char), 1, pF);
  	}  	
  	  	
  	fclose(pF);
  	ret = 0;  
  }
  
  

   return ret;
}
