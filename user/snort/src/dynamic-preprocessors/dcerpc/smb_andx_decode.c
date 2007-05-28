/*
 * smb_andx_decode.c
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
 * This performs the decoding of SMB AndX commands.
 *
 * NOTES:
 * - 08.12.04:  Initial Development.  SAS
 *
 */

#include <stdlib.h>
#include <wchar.h>

#include "debug.h"

#include "snort_dcerpc.h"
#include "smb_structs.h"
#include "smb_andx_structs.h"
#include "smb_andx_decode.h"
#include "dcerpc_util.h"
#include "dcerpc.h"

#define FIELD_ACCT_NAME 0
#define FIELD_PRIM_DOMAIN 1
#define SESS_AUTH_FIELD(i) ((i == FIELD_ACCT_NAME) ? "AccountName" : ((i == FIELD_PRIM_DOMAIN) ? "PrimaryDomain"  : "Unknown"))

#define FIELD_NATIVE_OS 0
#define FIELD_NATIVE_LANMAN 1
#define SESS_NATIVE_FIELD(i) ((i == FIELD_NATIVE_OS) ? "NativeOS" : ((i == FIELD_NATIVE_LANMAN) ? "NativeLanMan" : "Unknown"))

/* Externs */
extern DCERPC         *_dcerpc;
extern SFSnortPacket  *_dcerpc_pkt;
extern u_int8_t        _disable_smb_fragmentation;
extern u_int16_t       _max_frag_size;

static void ReassembleSMBWriteX(SMB_WRITEX_REQ *writeX, u_int8_t *smb_data);
static int SMB_Fragmentation(u_int8_t *smb_hdr, SMB_WRITEX_REQ *writeX,
                               u_int8_t *smb_data, u_int16_t data_size);


static void ReassembleSMBWriteX(SMB_WRITEX_REQ *writeX, u_int8_t *smb_data)
{
    SMB_WRITEX_REQ temp_writeX;
    unsigned int   smb_hdr_len = (u_int8_t *)writeX - _dcerpc_pkt->payload;
    unsigned int   writeX_len = smb_data - (u_int8_t *)writeX;

    /* Make sure we have room to fit into alternate buffer */
    if ( (smb_hdr_len + writeX_len + _dcerpc->write_andx_buf_len) > _dpd.altBufferLen )
    {
        _dpd.logMsg("Reassembled SMB packet greater than %d bytes, skipping.",
															_dpd.altBufferLen);
        return;
    }

    /* Mock up header */
    memcpy(&temp_writeX, writeX, writeX_len);
    temp_writeX.remaining = _dcerpc->write_andx_buf_len;
    temp_writeX.dataLength = _dcerpc->write_andx_buf_len;

    /* Copy headers into buffer */
    /* SMB Header */
    memcpy(_dpd.altBuffer, _dcerpc_pkt->payload, smb_hdr_len);
    _dcerpc_pkt->normalized_payload_size = smb_hdr_len;
    
    /* Write AndX header */
    memcpy(_dpd.altBuffer + _dcerpc_pkt->normalized_payload_size, &temp_writeX, writeX_len);
    _dcerpc_pkt->normalized_payload_size += writeX_len;

    /* Copy data into buffer */
    memcpy(_dpd.altBuffer + _dcerpc_pkt->normalized_payload_size, _dcerpc->write_andx_buf, _dcerpc->write_andx_buf_len);
    _dcerpc_pkt->normalized_payload_size += _dcerpc->write_andx_buf_len;

    _dcerpc_pkt->flags |= FLAG_ALT_DECODE;

    ProcessDCERPCMessage(_dcerpc_pkt->payload, _dcerpc->write_andx_buf, _dcerpc->write_andx_buf_len);

    /* Get ready for next write */
    DCERPC_FragFree(_dcerpc->write_andx_buf, _dcerpc->write_andx_buf_size);
    _dcerpc->write_andx_buf = NULL;
    _dcerpc->write_andx_buf_len = 0;
    _dcerpc->write_andx_buf_size = 0;
    _dcerpc->fragmentation &= ~SMB_FRAGMENTATION;
    _dcerpc->fragmentation &= ~SUSPEND_FRAGMENTATION;
}

int SMB_Fragmentation(u_int8_t *smb_hdr, SMB_WRITEX_REQ *writeX, u_int8_t *smb_data, u_int16_t data_size)
{
    u_char    fragmented = 0;
    u_int16_t writeX_length;
    u_char    success = 0;

    /* Check for fragmentation */
    if ( _disable_smb_fragmentation )
        return 0;

    /* If not yet reassembling, attempt to parse as full DCE/RPC packet */
    if ( !(_dcerpc->fragmentation & SMB_FRAGMENTATION) )
    {
        success = ProcessDCERPCMessage(smb_hdr, smb_data, data_size);

        if ( success )
            return 0;
    }

    /* Set up writeX buffer to save SMB data.  Ignore dataLengthHigh, since we won't
        handle fragments that big.  */
    writeX_length = writeX->dataLength;

    /* Allocate space for buffer
        For now, ignore offset, since servers seem to */
    if ( !(_dcerpc->fragmentation & SUSPEND_FRAGMENTATION) )
    {
        if ( _dcerpc->write_andx_buf == NULL )
        {
            if ( writeX_length > _max_frag_size )
                writeX_length = _max_frag_size;

            _dcerpc->write_andx_buf = (u_int8_t *) DCERPC_FragAlloc(NULL, 0, &writeX_length);

            if ( !_dcerpc->write_andx_buf )
                _dpd.fatalMsg("Failed to allocate space for SMB Write AndX\n");
        
            if ( writeX_length == 0 )
            {
                DEBUG_WRAP(_dpd.debugMsg(DEBUG_DCERPC, "Memcap reached, ignoring SMB fragmentation reassembly.\n"););

                DCERPC_FragFree(_dcerpc->write_andx_buf, 0);
                _dcerpc->write_andx_buf = NULL;
                _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;
                return 0;
            }

            _dcerpc->write_andx_buf_size = writeX_length;
            _dcerpc->write_andx_buf_len  = 0;
        }
        else
        {
            u_int16_t new_size;

            new_size = _dcerpc->write_andx_buf_size + writeX->dataLength;
            _dcerpc->write_andx_buf = (u_int8_t *) DCERPC_FragAlloc(_dcerpc->write_andx_buf, 
                                                _dcerpc->write_andx_buf_size, &new_size);

            if ( !_dcerpc->write_andx_buf )
                _dpd.fatalMsg("Failed to allocate space for SMB Write AndX\n");
        
            if ( new_size == _dcerpc->write_andx_buf_size )
            {
                DEBUG_WRAP(_dpd.debugMsg(DEBUG_DCERPC, "Memcap reached, suspending SMB fragmentation reassembly.\n"););

                _dcerpc->fragmentation |= SUSPEND_FRAGMENTATION;
                
                DCERPC_FragFree(_dcerpc->write_andx_buf, _dcerpc->write_andx_buf_size);
                _dcerpc->write_andx_buf = NULL;
                _dcerpc->write_andx_buf_len = 0;
                _dcerpc->write_andx_buf_size = 0;
                return 0;
            }

            _dcerpc->write_andx_buf_size = new_size;
        }
    }

    /* SMB frag */
    if ( writeX_length > (_dcerpc->write_andx_buf_size - _dcerpc->write_andx_buf_len) )
    {
        writeX_length = _dcerpc->write_andx_buf_size - _dcerpc->write_andx_buf_len;
    }
    memcpy(_dcerpc->write_andx_buf + _dcerpc->write_andx_buf_len, smb_data, writeX_length);
    _dcerpc->write_andx_buf_len += writeX_length;
    _dcerpc->fragmentation |= SMB_FRAGMENTATION;

    if ( IsCompleteDCERPCMessage(_dcerpc->write_andx_buf, _dcerpc->write_andx_buf_len) )
    {
        ReassembleSMBWriteX(writeX, smb_data);
        _dcerpc->fragmentation &= ~SMB_FRAGMENTATION;
    }

    return 0;
}


static int IsIPC(u_int8_t *s, u_int16_t len, u_int32_t isUnicode)
{
    u_int16_t i;
    u_int8_t unicode_ipc[] = { 'I', '\0', 'P', '\0', 'C', '\0', '$', '\0' };

    if ( isUnicode )
    {
        if ( len < 8 )
            return 0;

        for ( i = 0; i < (len - 8)/2; i++ )
        {
            if ( memcmp(s+(i*2), unicode_ipc, 8) == 0 )
                return 1;
        }
    }
    else
    {
        if ( len < 5 )
            return 0;

        for ( i = 0; i < (len - 5); i++ )
        {

            if ( memcmp(s+i, "\\IPC$", 5) == 0 )
                return 1;
        }
    }
    return 0;
}

int SkipBytes(u_int8_t *data, u_int16_t size)
{
    u_int16_t i = 0;

    while ( *data != 0 && i < size )
    {
        data++;
        i++;
    }

    return i;
}

int SkipBytesWide(u_int8_t *data, u_int16_t size)
{
    u_int16_t i = 0;

    while ( *data != 0 && i < size )
    {
        data += 2;
        i += 2;
    }

    return i;
}


int ProcessSMBTreeConnXReq(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size, u_int16_t total_size)
{
    SMB_TREE_CONNECTX_REQ *treeConnX = (SMB_TREE_CONNECTX_REQ *)data;
    u_int16_t byteCount = smb_ntohs(treeConnX->byteCount);
    u_int16_t passwdLen = smb_ntohs(treeConnX->passwdLen);
    unsigned char *smb_data = data + sizeof(SMB_TREE_CONNECTX_REQ);
    int skipBytes = 1;
    int isIPC = 0;

    size -= sizeof(SMB_TREE_CONNECTX_REQ);

    /* Sanity check */
    if ( byteCount > size )
        return 0;

    /* Password data */
    if (passwdLen > 0 && byteCount > 0)
    {
        /* This passwd will always be ASCII -- equiv of
         * CaseInsensitivePasswd field from SessSetupAndX message */
#ifdef DEBUG_DCERPC_PRINT
        printf("Password: %.*s\n", passwdLen, smb_data);
#endif
        /* Skip past the password -- no terminating NULL */
        if ( passwdLen > size )
            return 0;

        smb_data += passwdLen;

        if ( byteCount < passwdLen )
            return 0;

        byteCount -= (passwdLen);
    }

    /* Get path */
    if (HAS_UNICODE_STRINGS(smbHdr)) /* Service field is ALWAYS ascii */
    {
        if (*smb_data != '\0')
        {
#ifdef DEBUG_DCERPC_PRINT
            wprintf(L"Path: %s\n", smb_data);
#endif
            skipBytes = SkipBytesWide(smb_data, byteCount) + 2;
        }
        isIPC = IsIPC(smb_data, byteCount, 1L);
    }
    else
    {
        if (*smb_data != '\0')
        {
#ifdef DEBUG_DCERPC_PRINT
            printf("Path: %s\n", smb_data);
#endif
            skipBytes = SkipBytes(smb_data, size) + 1;
        }
        isIPC = IsIPC(smb_data, byteCount, 0L);
    }
    smb_data += skipBytes;
    byteCount -= skipBytes;

    if ( isIPC && _dcerpc->smb_state == STATE_START )
        _dcerpc->smb_state = STATE_GOT_TREE_CONNECT;

    /* Print out service field */
#ifdef DEBUG_DCERPC_PRINT
    if (*smb_data != '\0')
    {
        printf("Service: %s\n", smb_data);
    }
#endif

    /* Handle next andX command in this packet */
    if (treeConnX->andXCommand != SMB_NONE)
    {
        u_int16_t data_size;
        u_int16_t andXOffset = smb_ntohs(treeConnX->andXOffset);

        if ( andXOffset > total_size )
            return 0;
      
        /* Make sure we don't backtrack or look at the same data again */
        if ( andXOffset <= (data - (u_int8_t *)smbHdr) )
            return 0;

        /* Skip header, get size of remaining data */
        data_size = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(treeConnX->andXCommand, smbHdr,
                (u_int8_t *)smbHdr + andXOffset, data_size, total_size);        
    }

    return 0;
}


int ProcessSMBNTCreateX(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size, u_int16_t total_size)
{
    SMB_NTCREATEX_REQ *ntCreateX = (SMB_NTCREATEX_REQ *)data;

#ifdef DEBUG_DCERPC_PRINT
    int byteCount = smb_ntohs(ntCreateX->byteCount);
    unsigned char *smb_data = data + sizeof(SMB_NTCREATEX_REQ);
    
    /* Appears to be a pad in there to word-align if unicode */
    if (HAS_UNICODE_STRINGS(smbHdr))
    {
        smb_data++;
        byteCount--;
    }

    if (byteCount > 0)
    {
        int i=0;
        printf("Create/Open: ");
        for (i=0;i<byteCount;)
        {
             if (HAS_UNICODE_STRINGS(smbHdr))
            {
                wprintf(L"%c", smb_data[i]);
                i+=2;
            }
            else
            {
                printf("%c", smb_data[i]);
                i++;
            }
        }
        printf("\n");
    }
#endif

    if ( _dcerpc->smb_state == STATE_GOT_TREE_CONNECT )
        _dcerpc->smb_state = STATE_GOT_NTCREATE;

    /* Handle next andX command in this packet */
    if (ntCreateX->andXCommand != SMB_NONE)
    {
        u_int16_t data_size;
        u_int16_t andXOffset = smb_ntohs(ntCreateX->andXOffset);

        if ( andXOffset >= total_size )
            return 0;
       
        /* Make sure we don't backtrack or look at the same data again */
        if ( andXOffset <= (data - (u_int8_t *)smbHdr) )
            return 0;

        /* Skip header, get size of remaining data */
        data_size = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(ntCreateX->andXCommand, smbHdr,
            (u_int8_t *)smbHdr + andXOffset, data_size, total_size);        
    }

    return 0;
}

int ProcessSMBWriteX(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size, u_int16_t total_size)
{
    SMB_WRITEX_REQ *writeX = (SMB_WRITEX_REQ *)data;
    u_int8_t       *dce_stub_data;
    u_int16_t       data_size;

    /* Only process WriteAndX packet if it is part of a DCE/RPC session */
    if ( _dcerpc->smb_state != STATE_GOT_NTCREATE )
    {
        return 0;
    }

    if ( writeX->dataOffset >= total_size )
    {
        return 0;
    }

    dce_stub_data = (u_int8_t *)smbHdr + writeX->dataOffset;

#ifdef DEBUG_DCERPC_PRINT
    if (writeX->dataLength > 0)
    {
        int i=0;
        printf("Write: ");
        for (i=0;i<writeX->dataLength;i++)
        {
            printf("%c", dce_stub_data[i]);
        }
        printf("\n");
    }
#endif

    /* Get size of actual remaining SMB data in packet */
    data_size = total_size - (data - (u_int8_t *) smbHdr) - sizeof(SMB_HDR);

    SMB_Fragmentation((u_int8_t *) smbHdr, writeX, dce_stub_data, data_size);

    /* Handle next andX command in this packet */
    if (writeX->andXCommand != SMB_NONE)
    {
        u_int16_t andXOffset = smb_ntohs(writeX->andXOffset);

        if ( andXOffset >= total_size )
            return 0;
       
        /* Make sure we don't backtrack or look at the same data again */
        if ( andXOffset <= (data - (u_int8_t *)smbHdr) )
            return 0;

        /* Skip WriteX header, get size of remaining data */
        data_size = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(writeX->andXCommand, smbHdr,
            (u_int8_t *)smbHdr + andXOffset, data_size, total_size);        
    }

    return 0;
}

int ProcessSMBTransaction(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size, u_int16_t total_size)
{
    SMB_TRANS_REQ  *trans = (SMB_TRANS_REQ *)data;
    u_int8_t       *dce_stub_data;
    u_int16_t       data_size;

    /* Only process Trans packet if we think it is part of a DCE/RPC session 
         NTCREATE state is when we get the bind packet
         IS_DCERPC is when we get a request packet 
     */
    if ( _dcerpc->smb_state != STATE_GOT_NTCREATE )
    {
        return 0;
    }

    if ( trans->dataOffset >= total_size )
    {
        return 0;
    }

    /* We got a Tree Connect followed by a NTCreate, followed by Trans.  
        Assume DCE/RPC */
    _dcerpc->state = STATE_IS_DCERPC;

    /* This should be start of the DCE/RPC stub data */
    dce_stub_data = (u_int8_t *)smbHdr + trans->dataOffset;
 
    /* Get size of actual SMB data in packet */
    data_size = total_size - (data - (u_int8_t *) smbHdr) - sizeof(SMB_HDR);

    ProcessDCERPCMessage((u_char *)smbHdr, dce_stub_data, data_size);

#ifdef DEBUG_DCERPC_PRINT
    if (trans->totalDataCount > 0)
    {
        int i=0;
        printf("Write: ");
        for (i=0;i<trans->totalDataCount;i++)
        {
            printf("%c", dce_stub_data[i]);
        }
        printf("\n");
    }
#endif

    return 0;
}

int ProcessSMBReadX(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size, u_int16_t total_size)
{
    SMB_READX_REQ *readX = (SMB_READX_REQ *)data;
    u_int16_t       data_size;

    /* Handle next andX command in this packet */
    if (readX->andXCommand != SMB_NONE)
    {
        u_int16_t andXOffset = smb_ntohs(readX->andXOffset);

        if ( andXOffset >= total_size )
            return 0;
       
        /* Make sure we don't backtrack or look at the same data again */
        if ( andXOffset <= (data - (u_int8_t *)smbHdr) )
            return 0;

        /* Skip ReadX header, get size of remaining data */
        data_size = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(readX->andXCommand, smbHdr,
            (u_int8_t *)smbHdr + smb_ntohs(readX->andXOffset), data_size, total_size);        
    }

    return 0;
}


#ifdef UNUSED_SMB_COMMAND

int ProcessSMBSetupXReq(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size, u_int16_t total_size)
{
    int extraIndex = 0;
    SMB_SESS_SETUPX_REQ_HDR *sess_setupx_req_hdr = (SMB_SESS_SETUPX_REQ_HDR *)data;

    /* Ptr to first null terminated data element */
    unsigned char wordCount = smb_ntohs(sess_setupx_req_hdr->wordCount);
    /* Skip the common header portion, wordCount byte + parameter bytes * 2 */
    unsigned char *smb_data;
    short byteCount = 0, extraBytes = 0;
    int skipBytes = 1;

    int passwdLen = 0;
    char unicodePasswd = 0;

    switch (wordCount)
    {
    case 10:
        {
            /* Old session setup andx */
            SMB_SESS_SETUPX_REQ_AUTH_OLD *sess_setupx_auth = 
                (SMB_SESS_SETUPX_REQ_AUTH_OLD *)
                (data + sizeof(SMB_SESS_SETUPX_REQ_HDR));
            passwdLen = smb_ntohs(sess_setupx_auth->passwdLen);
            byteCount = extraBytes = smb_ntohs(sess_setupx_auth->byteCount);
            smb_data = data + sizeof(SMB_SESS_SETUPX_REQ_HDR) +
                sizeof(SMB_SESS_SETUPX_REQ_AUTH_OLD);
        }
        break;
    case 12:
        {
            /* Extended Security session setup andx */
            SMB_SESS_SETUPX_REQ_AUTH_NTLM12 *sess_setupx_auth =
                (SMB_SESS_SETUPX_REQ_AUTH_NTLM12 *)
                (data + sizeof(SMB_SESS_SETUPX_REQ_HDR));
            passwdLen = 0; /* Its a blob */
            byteCount = extraBytes = smb_ntohs(sess_setupx_auth->byteCount);
            skipBytes = smb_ntohs(sess_setupx_auth->secBlobLength);
            smb_data = data + sizeof(SMB_SESS_SETUPX_REQ_HDR) +
                sizeof(SMB_SESS_SETUPX_REQ_AUTH_NTLM12);
        }
        break;
    case 13:
        {
            /* Non-Extended Security session setup andx */
            SMB_SESS_SETUPX_REQ_AUTH_NTLM12_NOEXT *sess_setupx_auth =
                (SMB_SESS_SETUPX_REQ_AUTH_NTLM12_NOEXT *)
                (data + sizeof(SMB_SESS_SETUPX_REQ_HDR));
            if (sess_setupx_auth->passwdLen)
            {
                passwdLen = smb_ntohs(sess_setupx_auth->passwdLen);
                unicodePasswd = 1;
            }
            else if (sess_setupx_auth->iPasswdLen)
            {
                passwdLen = smb_ntohs(sess_setupx_auth->iPasswdLen);
            }
            byteCount = extraBytes = smb_ntohs(sess_setupx_auth->byteCount);
            smb_data = data + sizeof(SMB_SESS_SETUPX_REQ_HDR) +
                sizeof(SMB_SESS_SETUPX_REQ_AUTH_NTLM12_NOEXT);
        }
        break;
    default:
        return -1;
        break;
    }

    size -= sizeof(SMB_SESS_SETUPX_REQ_HDR);

    /* Password data */
    if (passwdLen)
    {
        int i=0;
        if ( unicodePasswd )
        {
#ifdef DEBUG_DCERPC_PRINT
            /* UNICODE Password */
            wprintf(L"Case Sensitive Password: %.*s\n", passwdLen, smb_data);
#endif
            /* Skip past the password -- no terminating NULL */
            smb_data += passwdLen;
            extraBytes -= passwdLen;

            /* Jump past the pad that re-aligns the next fields */
            if (HAS_UNICODE_STRINGS(smbHdr))
            {
                smb_data += 1;
                extraBytes -= 1;
            }
        }
        else
        {
#ifdef DEBUG_DCERPC_PRINT           
            /* ASCII Password */
            printf("Case Insensitive Password: %.*s\n", passwdLen, smb_data);
#endif
            /* Skip past the password -- no terminating NULL */
            smb_data += passwdLen;
            extraBytes -= passwdLen;

            /* Jump past the pad that re-aligns the next fields -- pad
             * is present when ascii password is an even # of bytes. */
            if (HAS_UNICODE_STRINGS(smbHdr) &&
                (passwdLen %2 == 0))
            {
                smb_data += 1;
                extraBytes -= 1;
            }       
        }

        for (i=0;i<2;i++)
        {
            skipBytes = 1;
            if (HAS_UNICODE_STRINGS(smbHdr))
            {
                if (*smb_data != '\0')
                {
#ifdef DEBUG_DCERPC_PRINT
                    printf("%s: ", SESS_AUTH_FIELD(extraIndex));
                    wprintf(L"%s\n", smb_data);
#endif
                    skipBytes = SkipBytesWide(smb_data, size) + 2;
                }
            }
            else
            {
                if (*smb_data != '\0')
                {
#ifdef DEBUG_DCERPC_PRINT
                    printf("%s: %s\n", SESS_AUTH_FIELD(extraIndex), smb_data);
#endif
                    skipBytes = SkipBytes(smb_data, size) + 1;
                }
            }
            extraIndex++;
            smb_data += skipBytes;
            extraBytes -= skipBytes;
        }
    }
    else
    {
#ifdef DEBUG_DCERPC_PRINT
        /* The security blob... */
        int i;
        printf("Security blob... ");
        for (i=0;i<skipBytes;i++)
        {
            if ( isprint(smb_data[i]) )
                printf("%c ", smb_data[i]);
            else
                printf("%.2x ", smb_data[i]);
        }
        printf("\n");
#endif
        smb_data += skipBytes;
        extraBytes -= skipBytes;

        /* Jump past the NULL Pad (ie fields following are word aligned) */
        if (skipBytes%2 == 0)
        {
            smb_data += 1;
            extraBytes -= 1;
        }

    }

    extraIndex = 0;

    /* Some extra data */
    while (extraBytes > 0)
    {
        skipBytes = 1;
        if (HAS_UNICODE_STRINGS(smbHdr))
        {
            if (*smb_data != '\0')
            {
#ifdef DEBUG_DCERPC_PRINT                
                printf("%s: ", SESS_NATIVE_FIELD(extraIndex));
                wprintf(L"%s\n", smb_data);
#endif
                skipBytes = wcslen(smb_data) + 1;
            }
            skipBytes *= 2;
        }
        else
        {
            if (*smb_data != '\0')
            {
#ifdef DEBUG_DCERPC_PRINT
                printf("%s: %s\n", SESS_NATIVE_FIELD(extraIndex), smb_data);
#endif
                skipBytes = strlen(smb_data) + 1;
            }
        }
        extraIndex++;
        smb_data += skipBytes;
        extraBytes -= skipBytes;
    }

    /* Handle next andX command in this packet */
    if (sess_setupx_req_hdr->andXCommand != SMB_NONE)
    {
        u_int16_t data_size;
        u_int16_t andXOffset = smb_ntohs(sess_setupx_req_hdr->andXOffset);

        if ( andXOffset >= total_size )
            return 0;
       
        /* Make sure we don't backtrack or look at the same data again */
        if ( andXOffset <= (data - (u_int8_t *)smbHdr) )
            return 0;

        /* Skip header, get size of remaining data */
        data_size = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(sess_setupx_req_hdr->andXCommand, smbHdr,
            (u_int8_t *)smbHdr + smb_ntohs(sess_setupx_req_hdr->andXOffset), data_size, total_size);        
    }

    return 0;
}


int ProcessSMBLogoffXReq(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size, u_int16_t total_size)
{
    SMB_LOGOFFX_REQ *logoffX = (SMB_LOGOFFX_REQ *)data;
    int byteCount = smb_ntohs(logoffX->byteCount);

    if (byteCount > 0)
    {
        return -1;
    }

    /* Handle next andX command in this packet */
    if (logoffX->andXCommand != SMB_NONE)
    {
        u_int16_t data_size;
        u_int16_t andXOffset = smb_ntohs(logoffX->andXOffset);

        if ( andXOffset >= total_size )
            return 0;
       
        /* Make sure we don't backtrack or look at the same data again */
        if ( andXOffset <= (data - (u_int8_t *)smbHdr) )
            return 0;

        /* Skip header, get size of remaining data */
        data_size = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(logoffX->andXCommand, smbHdr,
            (u_int8_t *)smbHdr + smb_ntohs(logoffX->andXOffset), data_size, total_size);        
    }

    return 0;
}




int ProcessSMBLockingX(SMB_HDR *smbHdr, u_int8_t *data, u_int16_t size, u_int16_t total_size)
{
    SMB_LOCKINGX_REQ *lockingX = (SMB_LOCKINGX_REQ *)data;
    unsigned char *smb_data = data + sizeof(SMB_LOCKINGX_REQ);

    u_int16_t numUnlocks = smb_ntohs(lockingX->numUnlocks);
    u_int16_t numLocks = smb_ntohs(lockingX->numLocks);
    int lockRangeSize;
    if (lockingX->lockType & LOCKINGX_LARGE_FILES)
    {
        lockRangeSize = sizeof(SMB_LARGEFILE_LOCKINGX_RANGE);
#ifdef DEBUG_DCERPC_PRINT
        if (numUnlocks > 0)
        {
            int i;
            printf("Unlocking PIDs: ");
            for (i=0;i<numUnlocks;i++)
            {
                SMB_LARGEFILE_LOCKINGX_RANGE *lock =
                    (SMB_LARGEFILE_LOCKINGX_RANGE *)(smb_data + 
                    lockRangeSize * i);
                printf("%d ", lock->pid);
            }
            printf("\n");
        }

        if (numLocks > 0)
        {
            int i;
            printf("Locking PIDs: ");
            for (i=0;i<numLocks;i++)
            {
                SMB_LARGEFILE_LOCKINGX_RANGE *lock =
                    (SMB_LARGEFILE_LOCKINGX_RANGE *)(smb_data + 
                    lockRangeSize * numUnlocks+ 
                    lockRangeSize * i);
                printf("%d ", lock->pid);
            }
            printf("\n");
        }
#endif
    }
    else
    {
        lockRangeSize = sizeof(SMB_LOCKINGX_RANGE);
#ifdef DEBUG_DCERPC_PRINT
        if (numUnlocks > 0)
        {
            printf("Unlocking PIDs: ");
            for (i=0;i<numUnlocks;i++)
            {
                SMB_LOCKINGX_RANGE *lock =
                    (SMB_LOCKINGX_RANGE *)(smb_data + 
                    lockRangeSize * i);
                printf("%d ", lock->pid);
            }
            printf("\n");
        }

        if (numLocks > 0)
        {
            printf("Locking PIDs: ");
            for (i=0;i<numLocks;i++)
            {
                SMB_LOCKINGX_RANGE *lock =
                    (SMB_LOCKINGX_RANGE *)(smb_data + 
                    lockRangeSize * numUnlocks+ 
                    lockRangeSize * i);
                printf("%d ", lock->pid);
            }
            printf("\n");
        }
#endif
    }
    
    /* Handle next andX command in this packet */
    if (lockingX->andXCommand != SMB_NONE)
    {
        u_int16_t data_size;
        u_int16_t andXOffset = smb_ntohs(lockingX->andXOffset);

        if ( andXOffset >= total_size )
            return 0;
       
        /* Make sure we don't backtrack or look at the same data again */
        if ( andXOffset <= (data - (u_int8_t *)smbHdr) )
            return 0;

        /* Skip header, get size of remaining data */
        data_size = total_size - andXOffset;

        /* Next block is at smbHdr + smb_ntohs(sess_setupx_req->andXOffset) */
        return ProcessNextSMBCommand(lockingX->andXCommand, smbHdr,
            (u_int8_t *)smbHdr + smb_ntohs(lockingX->andXOffset), data_size, total_size);        
    }

    return 0;
}



#endif /*  UNUSED_SMB_COMMAND */

