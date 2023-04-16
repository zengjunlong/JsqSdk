//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//

#ifndef _INTERFACES
#define _INTERFACES

#include "nfsrvext.h"

BOOLEAN interfaces_init();
void interfaces_free();

void interfaces_add(ULONG64 luid, PNF_ADDRESS pAddress);
void interfaces_clear();
BOOLEAN interfaces_get(ULONG64 luid, int ipFamily, PNF_ADDRESS pAddress);
BOOLEAN interfaces_isLocalAddress(ULONG64 luid, int ipFamily, PNF_ADDRESS pAddress);

#endif