/*
 * snort_dcerpc.c
 *
 * Copyright (C) 2004-2006 Sourcefire,Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Description:
 *
 * This performs the DCERPC decoding.
 *
 * Arguments:
 *   
 * Effect:
 *
 * None
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */

#include "debug.h"
#include "snort_dcerpc.h"
#include "smb_structs.h"
#include "smb_andx_decode.h"
#include "smb_file_decode.h"
#include "dcerpc.h"

#include "profiler.h"
#ifdef PERF_PROFILING
extern PreprocStats dcerpcPerfStats;
extern PreprocStats dcerpcDetectPerfStats;
extern PreprocStats dcerpcIgnorePerfStats;
extern int dcerpcDetectCalled;
#endif

extern char SMBPorts[65536/8];
extern char DCERPCPorts[65536/8];

extern u_int8_t _autodetect;
    

/* Session structure */
DCERPC    *_dcerpc;
/* Save packet so we don't have to pass it around */
SFSnortPacket *_dcerpc_pkt;



int ProcessRawSMB(u_int8_t *data, u_int16_t size)
{
    /* Must remember to convert stuff to host order before using it... */
    u_int16_t data_size;
    SMB_HDR *smbHdr;

    // Raw SMB also has 4 bytes prepended to SMB data
    data += sizeof(NBT_HDR);
    smbHdr = (SMB_HDR *)data;
    size -= sizeof(NBT_HDR);

    if (memcmp(smbHdr->protocol, "\xffSMB", 4) != 0)
    {
        /* Not an SMB request, nothing really to do here... */
        return 0;
    }

    if ( size < sizeof(SMB_HDR) )
    {
        /* Not enough data */
        return 0;
    }

    data_size = size - sizeof(SMB_HDR);

    return ProcessNextSMBCommand(smbHdr->command, smbHdr, data + sizeof(SMB_HDR), data_size, size);
}


inline int ProcessRawDCERPC(u_int8_t *data, u_int16_t size)
{
    return ProcessDCERPCMessage(NULL, data, size);
}

/*
 * Free SMB-specific related to this session
 *
 * @param   v   pointer to SMB session structure
 *
 * @return  none
 */
void DCERPC_SessionFree(void * v)
{
    DCERPC *x = (DCERPC *) v;

    if ( x && x->write_andx_buf )
        free(x->write_andx_buf);
    
    if ( x && x->dcerpc_req_buf )
        free(x->dcerpc_req_buf);

    if ( x )
        free(x);
      
    return;
}


/*
 * Do first-packet setup
 *
 * @param   p   standard Packet structure
 *
 * @return  1 if successful
 *          0 if not
 */
static int DCERPC_Setup(void *pkt)
{
	SFSnortPacket *p = (SFSnortPacket *)pkt;
    DCERPC *x = NULL;

	if ( !_dpd.streamAPI )
	{
		DEBUG_WRAP(_dpd.debugMsg(DEBUG_DCERPC, "Error: Failed to get Stream API - Stream not enabled?\n"););
        return 0;
	}

    /*  Get session pointer */
    if ( p->stream_session_ptr != NULL )
    {
        x = _dpd.streamAPI->get_application_data(p->stream_session_ptr, PP_DCERPC);
    }

    if ( x == NULL )
    {
        int size = sizeof(DCERPC);

        x = (DCERPC *) malloc(size);
        if ( x == NULL )
        {
            _dpd.fatalMsg("%s(%d) => Failed to allocate for SMB session data\n", 
                    _dpd.config_file, _dpd.config_line);
            return 1;
        }
        else
        {
            memset(x, 0, size);
   
            _dpd.streamAPI->set_application_data(p->stream_session_ptr, PP_DCERPC,
                                                    x, &DCERPC_SessionFree);        
        }
    }   
  
    _dcerpc = x;
    _dcerpc_pkt = p;

	return 1;
}

int DCERPC_AutoDetect(u_int8_t *data, u_int16_t size)
{
    NBT_HDR *nbtHdr;
    int is_smb = 0;
    SMB_HDR *smbHdr;
    DCERPC_HDR     *dcerpc;

    if ( !_autodetect )
    {
        return 0;
    }

    if ( size >= (sizeof(NBT_HDR) + sizeof(SMB_HDR)) )
    {
        /* See if this looks like SMB */
        smbHdr = (SMB_HDR *) (data + sizeof(NBT_HDR));

        if (memcmp(smbHdr->protocol, "\xffSMB", 4) == 0)
        {
            /* Do an extra check on NetBIOS header, which should be valid for both
               NetBIOS and raw SMB */
            nbtHdr = (NBT_HDR *)data;

            if (nbtHdr->type == SMB_SESSION )
            {
                is_smb = 1;
            }
        }

        if ( is_smb )
        {
            /* Process as SMB */
            return ProcessRawSMB(data, size);            
        }
    }

    /* Might be DCE/RPC */

    /*  Make sure it's a reasonable size */
    dcerpc = (DCERPC_HDR *) data;

    if ( size < sizeof(DCERPC_REQ) )
    {
        return 0;
    }

    /*  Minimal DCE/RPC check - check for version and request */
    if ( dcerpc->version != 5 || dcerpc->packet_type != DCERPC_REQUEST )
    {
        return 0;
    }

    return ProcessRawDCERPC(data, size);
}

int DCERPCDecode(void *pkt)
{
    SFSnortPacket *p = (SFSnortPacket *) pkt;
	
    if ( DCERPC_Setup(p) == 0 )
    {
    	return 0;
    }

    /* Don't examine if the packet is rebuilt 
        TODO:  Not a final solution! */
    if ( p->flags & FLAG_REBUILT_STREAM )
        return 0;

    if ( _autodetect )
        return DCERPC_AutoDetect(p->payload, p->payload_size);
    
    /* check the port list */
    if ( SMBPorts[(p->dst_port/8)] & (1<<(p->dst_port%8)) )
    {
        /* Raw SMB */
        return ProcessRawSMB(p->payload, p->payload_size);
    }

    if ( DCERPCPorts[(p->dst_port/8)] & (1<<(p->dst_port%8)) )
    {
        return ProcessRawDCERPC(p->payload, p->payload_size);
    }

    return 0;
}

void DCERPC_Exit(void)
{
#ifdef PERF_PROFILING
#ifdef DEBUG_DCERPC_PRINT
    printf("SMB Debug\n");
    printf("  Number of packets seen:      %u\n", dcerpcPerfStats.checks);
    printf("  Number of packets ignored: %d\n", dcerpcIgnorePerfStats.checks);
#endif
#endif
}


int ProcessNextSMBCommand(u_int8_t command, SMB_HDR *smbHdr,
                          u_int8_t *data, u_int16_t size, u_int16_t total_size)
{
    switch (command)
    {
        case SMB_COM_TREE_CONNECT_ANDX:
            return ProcessSMBTreeConnXReq(smbHdr, data, size, total_size);
        case SMB_COM_NT_CREATE_ANDX:
            return ProcessSMBNTCreateX(smbHdr, data, size, total_size);
        case SMB_COM_WRITE_ANDX: 
            return ProcessSMBWriteX(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION:
            return ProcessSMBTransaction(smbHdr, data, size, total_size);
        case SMB_COM_READ_ANDX:
            return ProcessSMBReadX(smbHdr, data, size, total_size);

#ifdef UNUSED_SMB_COMMAND

        case SMB_COM_SESSION_SETUP_ANDX:
            return ProcessSMBSetupXReq(smbHdr, data, size, total_size);
        case SMB_COM_LOGOFF_ANDX:
            return ProcessSMBLogoffXReq(smbHdr, data, size, total_size);
        case SMB_COM_READ_ANDX:
            return ProcessSMBReadX(smbHdr, data, size, total_size);
        case SMB_COM_LOCKING_ANDX:
            return ProcessSMBLockingX(smbHdr, data, size, total_size);

        case SMB_COM_NEGOTIATE:
            return ProcessSMBNegProtReq(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION2:
            return ProcessSMBTransaction2(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION2_SECONDARY:
            return ProcessSMBTransaction2Secondary(smbHdr, data, size, total_size);
        case SMB_COM_NT_TRANSACT:
            return ProcessSMBNTTransact(smbHdr, data, size, total_size);
        case SMB_COM_NT_TRANSACT_SECONDARY:
            return ProcessSMBNTTransactSecondary(smbHdr, data, size, total_size);
        case SMB_COM_TRANSACTION_SECONDARY:
            break;
        
        case SMB_COM_ECHO:
            return ProcessSMBEcho(smbHdr, data, size, total_size);
        case SMB_COM_SEEK:
            return ProcessSMBSeek(smbHdr, data, size, total_size);
        case SMB_COM_FLUSH:
            return ProcessSMBFlush(smbHdr, data, size, total_size);
        case SMB_COM_CLOSE:
        case SMB_COM_CLOSE_AND_TREE_DISC:
            return ProcessSMBClose(smbHdr, data, size, total_size);
        case SMB_COM_TREE_DISCONNECT:
        case SMB_COM_NT_CANCEL:
            return ProcessSMBNoParams(smbHdr, data, size, total_size);
#endif
        default:
#ifdef DEBUG_DCERPC_PRINT
            printf("====> Unprocessed command 0x%02x <==== \n", command);
#endif
            break;
    }

    return 0;
}

