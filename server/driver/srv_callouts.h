//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#ifndef _SRV_CALLOUTS
#define _SRV_CALLOUTS

#include "nfsrvext.h"
#include "hashtable.h"

NTSTATUS srvcallouts_init();
void srvcallouts_free();
void srvcallouts_cleanup();

VOID srvcallouts_MacFrameCallout(
   IN const FWPS_INCOMING_VALUES* inFixedValues,
   IN const FWPS_INCOMING_METADATA_VALUES* inMetaValues,
   IN VOID* packet,
   IN const void* classifyContext,
   IN const FWPS_FILTER* filter,
   IN UINT64 flowContext,
   OUT FWPS_CLASSIFY_OUT* classifyOut);

NTSTATUS srvcallouts_MacFrameNotify(
    IN  FWPS_CALLOUT_NOTIFY_TYPE        notifyType,
    IN  const GUID*             filterKey,
    IN  const FWPS_FILTER*     filter);

BOOLEAN srvcallouts_getDestinationAddress(char protocol, PNF_ADDRESS srcAddress, PNF_ADDRESS dstAddress);
BOOLEAN srvcallouts_updateUDPDestinationAddress(PNF_ADDRESS srcAddress, PNF_ADDRESS dstAddress, PNF_ADDRESS newDstAddress);

void srvcallouts_setTimeout(PNF_SRV_TIMEOUT pt);

#endif
