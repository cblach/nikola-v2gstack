/*====================================================================*
 *
 *   Copyright (c) 2013 Qualcomm Atheros, Inc.
 *
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or
 *   without modification, are permitted (subject to the limitations
 *   in the disclaimer below) provided that the following conditions
 *   are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   * Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the following
 *     disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *   * Neither the name of Qualcomm Atheros nor the names of
 *     its contributors may be used to endorse or promote products
 *     derived from this software without specific prior written
 *     permission.
 *
 *   NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE
 *   GRANTED BY THIS LICENSE. THIS SOFTWARE IS PROVIDED BY THE
 *   COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 *   IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 *   PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 *   OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 *   HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *   CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 *   OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *--------------------------------------------------------------------*/

/*====================================================================*
 *
 *   homeplug.h - HomePlug Definitions and Declarations;
 *
 *.  Qualcomm Atheros HomePlug AV Powerline Toolkit
 *:  Copyright (c) 2009-2013 by Qualcomm Atheros Inc. ALL RIGHTS RESERVED;
 *;  For demonstration and evaluation only; Not for production use.
 *
 *   Contributor(s):
 *	Charles Maier <cmaier@qca.qualcomm.com>
 *	Alex Vasquez <alex.vasquez@qca.qualcomm.com>
 *
 *--------------------------------------------------------------------*/

#ifndef HOMEPLUG_HEADER
#define HOMEPLUG_HEADER

/*====================================================================*
 *   HomePlug AV Constants;
 *--------------------------------------------------------------------*/

#define HOMEPLUG_MMV 0x01
#define HOMEPLUG_MMTYPE 0x0000

/*====================================================================*
 * HomePlug Management Message Ranges for Information Only;
 *--------------------------------------------------------------------*/

#define CC_MMTYPE_MIN 0x0000
#define CC_MMTYPE_MAX 0x1FFF
#define CP_MMTYPE_MIN 0x2000
#define CP_MMTYPE_MAX 0x3FFF
#define NN_MMTYPE_MIN 0x4000
#define NN_MMTYPE_MAX 0x5FFF
#define CM_MMTYPE_MIN 0x6000
#define CM_MMTYPE_MAX 0x7FFF
#define MS_MMTYPE_MIN 0x8000
#define MS_MMTYPE_MAX 0x9FFF
#define VS_MMTYPE_MIN 0xA000
#define VS_MMTYPE_MAX 0xBFFF
#define HA_MMTYPE_MIN 0xC000
#define HA_MMTYPE_MAX 0xFFFF

/*====================================================================*
 * HomePlug AV MMEs have 4 variants indicated by the 2 MMTYPE LSBs;
 *--------------------------------------------------------------------*/

#define MMTYPE_CC 0x0000u
#define MMTYPE_CP 0x2000u
#define MMTYPE_NN 0x4000u
#define MMTYPE_CM 0x6000u
#define MMTYPE_MS 0x8000u
#define MMTYPE_VS 0xA000u
#define MMTYPE_XX 0xC000u

#ifndef IHPAPI_HEADER
#define MMTYPE_REQ 0x0000u
#define MMTYPE_CNF 0x0001u
#define MMTYPE_IND 0x0002u
#define MMTYPE_RSP 0x0003u
#define MMTYPE_MODE  (MMTYPE_REQ|MMTYPE_CNF|MMTYPE_IND|MMTYPE_RSP)
#define MMTYPE_MASK ~(MMTYPE_REQ|MMTYPE_CNF|MMTYPE_IND|MMTYPE_RSP)
#endif

/*====================================================================*
 * HomePlug AV Management Message Types;
 *--------------------------------------------------------------------*/

#define CC_CCO_APPOINT 0x0000u
#define CC_BACKUP_APPOINT 0x0004u
#define CC_LINK_INFO 0x0008u
#define CC_HANDOVER 0x000Cu
#define CC_HANDOVER_INFO 0x0010u
#define CC_DISCOVER_LIST 0x0014u
#define CC_LINK_NEW 0x0018u
#define CC_LINK_MOD 0x001Cu
#define CC_LINK_SQZ 0x0020u
#define CC_LINK_REL 0x0024u
#define CC_DETECT_REPORT 0x0028u
#define CC_WHO_RU 0x002Cu
#define CC_ASSOC 0x0030u
#define CC_LEAVE 0x0034u
#define CC_SET_TEI_MAP 0x0038u
#define CC_RELAY 0x003Cu
#define CC_BEACON_RELIABILITY 0x0040u
#define CC_ALLOC_MOVE 0x0044u
#define CC_ACCESS_NEW 0x0048u
#define CC_ACCESS_REL 0x004Cu
#define CC_DCPPC 0x0050u
#define CC_HP1_DET 0x0054u
#define CC_BLE_UPDATE 0x0058u
#define CP_PROXY_APPOINT 0x2000u
#define PH_PROXY_APPOINT 0x2004u
#define CP_PROXY_WAKE 0x2008u
#define NN_INL 0x4000u
#define NN_NEW_NET 0x4004u
#define NN_ADD_ALLOC 0x4008u
#define NN_REL_ALLOC 0x400Cu
#define NN_REL_NET 0x4010u
#define CM_ASSOCIATED_STA 0x6000u
#define CM_ENCRYPTED_PAYLOAD 0x6004u
#define CM_SET_KEY 0x6008u
#define CM_GET_KEY 0x600Cu
#define CM_SC_JOIN 0x6010u
#define CM_CHAN_EST 0x6014u
#define CM_TM_UPDATE 0x6018u
#define CM_AMP_MAP 0x601Cu
#define CM_BRG_INFO 0x6020u
#define CM_CONN_NEW 0x6024u
#define CM_CONN_REL 0x6028u
#define CM_CONN_MOD 0x602Cu
#define CM_CONN_INFO 0x6030u
#define CM_STA_CAP 0x6034u
#define CM_NW_INFO 0x6038u
#define CM_GET_BEACON 0x603Cu
#define CM_HFID 0x6040u
#define CM_MME_ERROR 0x6044u
#define CM_NW_STATS 0x6048u
#define CM_SLAC_PARAM 0x6064u
#define CM_START_ATTEN_CHAR 0x6068u
#define CM_ATTEN_CHAR 0x606Cu
#define CM_PKCS_CERT 0x6070u
#define CM_MNBC_SOUND 0x6074u
#define CM_VALIDATE 0x6078u
#define CM_SLAC_MATCH 0x607Cu
#define CM_SLAC_USER_DATA 0x6080u
#define CM_ATTEN_PROFILE 0x6084u

/*====================================================================*
 *
 *--------------------------------------------------------------------*/

#endif
