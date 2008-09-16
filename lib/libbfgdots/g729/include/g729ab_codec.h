/*****************************************************************************
Developed by Analog Devices Australia - Unit 3, 97 Lewis Road,
Wantirna, Victoria, Australia, 3152.  Email: ada.info@analog.com

Analog Devices, Inc.
BSD-Style License

libgdots
Copyright (c) 2007 Analog Devices, Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:
  - Redistributions of source code must retain the above copyright
    notice, this list of conditions and the following disclaimer.
  - Redistributions in binary form must reproduce the above copyright
    notice, this list of conditions and the following disclaimer in
    the documentation and/or other materials provided with the
    distribution.
  - Neither the name of Analog Devices, Inc. nor the names of its
    contributors may be used to endorse or promote products derived
    from this software without specific prior written permission.
  - The use of this software may or may not infringe the patent rights
    of one or more patent holders.  This license does not release you
    from the requirement that you obtain separate licenses from these
    patent holders to use this software.

THIS SOFTWARE IS PROVIDED BY ANALOG DEVICES "AS IS" AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, NON-INFRINGEMENT,
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL ANALOG DEVICES BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, INTELLECTUAL PROPERTY RIGHTS, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
******************************************************************************

Project:	G.729 for Blackfin
Title:		G.729 decoder state buffer structure and function prototype
Author(s):	E. HSU
Revised by:     David Rowe October 2006, changed threading model to improve
                efficiency

Description: Main G.729AB codec header file

*****************************************************************************/
#ifndef G729AB_CODEC_H
#define G729AB_CODEC_H


#if defined(G729_MULTI_INST)
#include <pthread.h>
#include <errno.h>

static pthread_mutex_t g729_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#define DEC_ERROR_HANDLER 		1
#define G729_DEC_ERROR	 		2
#define G729_DEC_VERSION 		3
#define G729_DEC_INPUTFORMAT		4
#define G729_DEC_VERSION_NO		0x0140

typedef struct DECINST {
		short DecoderBuffer[893]; 
		short Input_Format;   		
  		void (* ErrorHandler)();
    	int		errorcode;    	
} G729_DecObj;

typedef G729_DecObj * G729_dec_h;

/* Function ptrs for g729 library functions so we can support dlopen() 
   with .so version.  These need to be initialised before lib is used,
   in both flat and .so versions */
void (*g729ab_dec_reset)(G729_dec_h svptr);
void (*g729ab_dec_process)(G729_dec_h svptr, short *data_ptr, short *pcm_ptr);

/*
**
** Function:            G729AB_DEC_PROCESS()
**
** Description:         Encoder Processing routine.
** Arguments:
**  svptr		Instance handle.
**  data_ptr   		Pointer pointing to the index input data.
**  pcm_ptr    		Pointer pointing to the PCM speech output data.
** Outputs:             The results of processing are stored in the memory
**			location pointed to by pcm_ptr.
** Return value:        Returns 1.
**
*/
void G729AB_DEC_PROCESS(G729_dec_h svptr, short *data_ptr, short *pcm_ptr);
void G729AB_DEC(G729_dec_h svptr, short *data_ptr, short *pcm_ptr)
{
#if defined(G729_MULTI_INST)
	pthread_mutex_lock(&g729_mutex);
#endif
	(*g729ab_dec_process)(svptr, data_ptr, pcm_ptr);
#if defined(G729_MULTI_INST)
	pthread_mutex_unlock(&g729_mutex);	
#endif	
};

/*
**
** Function:            G729_DEC_RESET()
**
** Description:         Resets the member variables within the given instance
**                      to their default values.
** Arguments:
**  svptr		Handle to the instance that is to be reset.
** Outputs:             None.
** Return value:        Returns 1.
**
*/
void G729AB_DEC_RESET(G729_dec_h svptr);

/*
**
** Function:            G729AB_DEC_CONFIG()
** Description:         Configure the given instance with the given
**                      configuration values.
** Arguments:
**  svptr		Instance handle.
**  Enum		Item to be configured.
**  value		Configuration value for the specified item.
** Outputs:             The specified item is configured with the value specified
** Return value:        Returns 1 if configuration successful, 0 otherwise.
*/

static inline int G729AB_DEC_CONFIG (G729_dec_h svptr,int Enum,int value) {
    switch(Enum) {
        case G729_DEC_INPUTFORMAT:	svptr->Input_Format=(short) value;  return 1;		
        case DEC_ERROR_HANDLER: svptr->ErrorHandler=(void (*)()) value; return 1;        
        default: return 0;
    }
}

/*
**
** Function:            G729AB_DEC_STATUS()
** Description:         Returns the required status from the given instance.
** Arguments:
**  svptr     		The handle to the instance.
**  Enum		Status item to return.
** Outputs:             None.
** Return value:        Returns value for specified item.
*/

static inline int G729AB_DEC_STATUS(G729_dec_h svptr, unsigned Enum) {
    switch(Enum) {
        case G729_DEC_ERROR:   return svptr->errorcode;
        case G729_DEC_VERSION: return G729_DEC_VERSION_NO;
        default:               return 0;
    }
}

/*****************************************************************************/

#define G729_ENC_VERSION_NO 	0x0140

#define ENC_ERROR_HANDLER 		1
#define G729_ENC_ERROR	 		2
#define G729_ENC_VERSION 		3
#define G729_ENC_VAD	 		4
#define G729_ENC_OUTPUTFORMAT	5

#define _Vad_enable_offset		2108


typedef struct {
  	short CoderBuffer[1054];  	
  	short Vad_enable;    
   	short extra;
   	int output_format;
  	void (* ErrorHandler)();
    int	errorcode;    
} G729_EncObj;

typedef G729_EncObj * G729_enc_h;

/* Function ptrs for g729 library functions so we can support dlopen() 
   with .so version.  These need to be initialised before lib is used,
   in both flat and .so versions */
void (*g729ab_enc_reset)(G729_enc_h svptr);
void (*g729ab_enc_process)(G729_enc_h svptr, short *pcm_ptr, short *data_ptr);

/*
**
** Function:            G729AB_ENC_PROCESS()
** Description:         Encoder Processing routine.
** Arguments:
**  svptr		Instance handle.
**  pcm_ptr     	Pointer pointing to the PCM speech input data.
**  data_ptr     	Pointer pointing to the index output data.
** Outputs:             The results of processing are stored in the memory
**			location pointed to by data_ptr.
** Return value:        None.
**
*/
void G729AB_ENC_PROCESS(G729_enc_h svptr, short * pcm_ptr, short * data_ptr);
void G729AB_ENC(G729_enc_h svptr, short * pcm_ptr, short * data_ptr)
{
#if defined(G729_MULTI_INST)
	pthread_mutex_lock(&g729_mutex);
#endif
        (*g729ab_enc_process)(svptr, pcm_ptr, data_ptr);
#if defined(G729_MULTI_INST)
        pthread_mutex_unlock(&g729_mutex);
#endif
}

/*
** Function:            G729AB_ENC_RESET()
** Description:         Resets the member variables within the given instance
**                      to their default values.
** Arguments:
**   svptr 		Handle to the instance that is to be reset.
** Outputs:             None.
** Return value:        None.
*/
void G729AB_ENC_RESET(G729_enc_h svptr);

/*
** Function:            G729_ENC_CONFIG()
** Description:         Configure the given instance with the given
**                      configuration values.
** Arguments:
**  svptr	   	The handle to the instance that is to be configured.
**  Enum		Item to configure.
**  value		Configuration value.
** Outputs:             None.
** Return value:        Returns 1 if configuration successful, 0 otherwise.
*/

static inline int G729AB_ENC_CONFIG(G729_enc_h  svptr, unsigned Enum, unsigned value)
{
    switch(Enum) {
		case G729_ENC_VAD: 	    svptr->Vad_enable=(short)  value;	return 1;
		case ENC_ERROR_HANDLER: svptr->ErrorHandler=(void (*)()) value; return 1;  
		case G729_ENC_OUTPUTFORMAT: 		 svptr->output_format =  value;	return 1;			
        default: return 0;
    }
}

/*
** Function:            G729AB_ENC_STATUS()
** Description:         Returns the required status from the given instance.
** Arguments:
**  svptr	  	The handle to the instance.
**  Enum		Status item to return.
** Outputs:             None.
** Return value:        Returns the requested status value.
*/

static inline int G729AB_ENC_STATUS(G729_enc_h svptr, unsigned Enum)
{
    switch(Enum)    {
        case G729_ENC_ERROR:        return svptr->errorcode;
        case G729_ENC_VERSION:     	return G729_ENC_VERSION_NO;
        default:            return 0;
    }
}

#endif /* #ifndef G729AB_CODEC_H */
