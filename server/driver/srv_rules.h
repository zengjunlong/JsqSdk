//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#ifndef _SRVRULES_H
#define _SRVRULES_H

#include "hashtable.h"
#include "nfsrvext.h"

typedef struct _SRV_PACKET_INFO
{
	UCHAR			ipFamily;
	UCHAR			protocol;
	NF_ADDRESS		srcAddress;
	NF_ADDRESS		dstAddress;
	BOOLEAN			isOutbound;
	UINT64			interfaceLuid;
	UINT			payloadLength;
	BOOLEAN			isFragment;
	BOOLEAN			isLastFragment;
	UINT			fragOffset;
	UINT			fragId;
	HASH_ID			payloadHash;
} SRV_PACKET_INFO, *PSRV_PACKET_INFO;


NTSTATUS srvrules_init();
void srvrules_free();

void srvrules_add(PNF_SRV_RULE pRule, BOOLEAN toHead);
void srvrules_remove_all();
BOOLEAN srvrules_isEmpty();

BOOLEAN srvrules_add_temp(PNF_SRV_RULE pRule);
void srvrules_remove_all_temp();
void srvrules_set_temp();

BOOLEAN srvrules_find(PSRV_PACKET_INFO pPacketInfo, PNF_SRV_RULE_ACTION pAction);

#endif