//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//

#ifndef _IPFRAG
#define _IPFRAG

#include "srv_rules.h"

typedef struct _NF_PORTS
{
	unsigned short	srcPort;
	unsigned short	dstPort;
} NF_PORTS, *PNF_PORTS;

BOOLEAN ipfrag_init();
void ipfrag_free();

BOOLEAN ipfrag_add(PSRV_PACKET_INFO pPacketInfo, PNF_SRV_RULE_ACTION pAction);
BOOLEAN ipfrag_lookup(PSRV_PACKET_INFO pPacketInfo, PNF_PORTS pPorts, PNF_SRV_RULE_ACTION pAction);
void ipfrag_removeAll();
void ipfrag_deleteExpiredEntries();

#endif