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
#define MAGIC_CRC 0x12345678 /* Alternative valid signature; backward compatibility */ 

struct DATA_STORAGE {
	unsigned short size; /* Structure size [Bytes] including length field but without crc field. */ 
	unsigned char mac[MAC_LEN]; /* Ethernet hardware address */
	/* optionaly: Add more hardware related properties like serial number string */
	
	int crc32; /* CRC checksum of remaining structure */
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
	 	
  	fread(pBuf, sizeof(unsigned short), 1, pF);
  	cfg.size = *(unsigned short*)pBuf; 	
	 	
  	for(i=0; i<MAC_LEN; i++)
  	{
  		fread(pBuf, sizeof(unsigned char), 1, pF);
  		tmp = *(unsigned char*)pBuf;
  		cfg.mac[i] = (unsigned int) tmp;
  	}
  	
  	fread(pBuf, sizeof(int), 1, pF);
  	cfg.crc32 = *(int*)pBuf;
  	
  	if( MAGIC_CRC != cfg.crc32)
  	{
  		printf("Invalid or empty board environment!\n");
  		return -1;
  	}

	printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", cfg.mac[0], cfg.mac[1], cfg.mac[2], cfg.mac[3], cfg.mac[4], cfg.mac[5]);
	fclose(pF);
	ret = 0;
  } 
  else 
  {
  	/* store new configuration data */
  	
  	/* ToDo: Do not allow MAC modification in case of a existing configuration */	  
  	 	
  	
	if( 0 == strcmp("--reset", argv[1]) )
	{		
		memset(&cfg, 0, sizeof( struct DATA_STORAGE));
		
		pF = fopen(ENV_BOARD_PARTITION, "wb"); 		
		fwrite(&cfg, sizeof( struct DATA_STORAGE), 1, pF);				
		printf("Board environment content cleared.\n");
  		fclose(pF);		
		return 0;
	}  	
  	
  		  
  	pStrMacAddr = argv[1];  	  
  	/*printf("%s\n", pStrMacAddr); */	
  	tmp = sscanf(pStrMacAddr, "%2x:%2x:%2x:%2x:%2x:%2x", &tmpMac[0], &tmpMac[1], &tmpMac[2], &tmpMac[3], &tmpMac[4], &tmpMac[5] );
  	
  	if( MAC_LEN != tmp)
	{
		printf("Invalid format!\n");
		return -1;
	}  	  	
  	
  	  		  
	pF = fopen(ENV_BOARD_PARTITION, "wb"); 
	cfg.size = sizeof(struct DATA_STORAGE) - sizeof(int);
	fwrite(&cfg.size, sizeof(unsigned short), 1, pF);	
  	
  	for(i=0; i<MAC_LEN; i++)
  	{
  		cfg.mac[i] = (unsigned char)tmpMac[i];
  		fwrite(&cfg.mac[i], sizeof(unsigned char), 1, pF);
  	}

	cfg.crc32 = MAGIC_CRC;
	fwrite(&cfg.crc32, sizeof(int), 1, pF);	  	  	
  	  	
  	fclose(pF);
  	ret = 0;  
  }
  

   return ret;
}

