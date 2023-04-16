//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#include "stdinc.h"
#include "dynlink.h"
#include "wfplink.h"

#ifdef _WPPTRACE
#include "wfplink.tmh"
#endif

static int g_windowsVersion = 7;

t_FwpmBfeStateGet0		pFwpmBfeStateGet0 = NULL;
t_FwpmBfeStateSubscribeChanges0 pFwpmBfeStateSubscribeChanges0 = NULL;
t_FwpmBfeStateUnsubscribeChanges0 pFwpmBfeStateUnsubscribeChanges0 = NULL;
t_FwpsCalloutRegister1	pFwpsCalloutRegister1 = NULL;
t_FwpsCalloutUnregisterByKey0 pFwpsCalloutUnregisterByKey0 = NULL;
t_FwpmTransactionBegin0 pFwpmTransactionBegin0 = NULL;
t_FwpmTransactionCommit0 pFwpmTransactionCommit0 = NULL;
t_FwpmEngineClose0		pFwpmEngineClose0 = NULL;
t_FwpmCalloutAdd0		pFwpmCalloutAdd0 = NULL;
t_FwpmFilterAdd0		pFwpmFilterAdd0 = NULL;
t_FwpmSubLayerCreateEnumHandle0 pFwpmSubLayerCreateEnumHandle0 = NULL;
t_FwpmSubLayerEnum0		pFwpmSubLayerEnum0 = NULL;
t_FwpmFreeMemory0		pFwpmFreeMemory0 = NULL;
t_FwpmSubLayerDestroyEnumHandle0 pFwpmSubLayerDestroyEnumHandle0 = NULL;
t_FwpmSubLayerAdd0		pFwpmSubLayerAdd0 = NULL;
t_FwpmTransactionAbort0	pFwpmTransactionAbort0 = NULL;
t_FwpmEngineOpen0		pFwpmEngineOpen0 = NULL;
t_FwpmProviderAdd0		pFwpmProviderAdd0 = NULL;
t_FwpmSubLayerDeleteByKey0	pFwpmSubLayerDeleteByKey0 = NULL;
t_FwpmProviderContextDeleteByKey0 pFwpmProviderContextDeleteByKey0 = NULL;
t_FwpsInjectionHandleCreate0 pFwpsInjectionHandleCreate0 = NULL;
t_FwpsInjectionHandleDestroy0 pFwpsInjectionHandleDestroy0 = NULL;
t_FwpsCopyStreamDataToBuffer0 pFwpsCopyStreamDataToBuffer0 = NULL;
t_FwpsFreeCloneNetBufferList0 pFwpsFreeCloneNetBufferList0 = NULL;
t_FwpsStreamInjectAsync0 pFwpsStreamInjectAsync0 = NULL;
t_FwpsAllocateNetBufferAndNetBufferList0 pFwpsAllocateNetBufferAndNetBufferList0 = NULL;
t_FwpsFreeNetBufferList0 pFwpsFreeNetBufferList0 = NULL;
t_FwpsConstructIpHeaderForTransportPacket0 pFwpsConstructIpHeaderForTransportPacket0 = NULL;
t_FwpsInjectNetworkSendAsync0 pFwpsInjectNetworkSendAsync0 = NULL;
t_FwpsInjectNetworkReceiveAsync0 pFwpsInjectNetworkReceiveAsync0 = NULL;
t_FwpsInjectTransportSendAsync0 pFwpsInjectTransportSendAsync0 = NULL;
t_FwpsInjectTransportReceiveAsync0 pFwpsInjectTransportReceiveAsync0 = NULL;
t_FwpsAcquireWritableLayerDataPointer0 pFwpsAcquireWritableLayerDataPointer0 = NULL;
t_FwpsApplyModifiedLayerData0 pFwpsApplyModifiedLayerData0 = NULL;
t_FwpsFlowAbort0 pFwpsFlowAbort0 = NULL;
t_FwpsFlowAssociateContext0 pFwpsFlowAssociateContext0 = NULL;
t_FwpsFlowRemoveContext0 pFwpsFlowRemoveContext0 = NULL;
t_FwpsCloneStreamData0 pFwpsCloneStreamData0 = NULL;
t_FwpsDiscardClonedStreamData0 pFwpsDiscardClonedStreamData0 = NULL;
t_FwpsCompleteClassify0 pFwpsCompleteClassify0 = NULL;
t_FwpsRedirectHandleDestroy0 pFwpsRedirectHandleDestroy0 = NULL;
t_FwpsReleaseClassifyHandle0 pFwpsReleaseClassifyHandle0 = NULL;
t_FwpsQueryPacketInjectionState0 pFwpsQueryPacketInjectionState0 = NULL;
t_FwpsPendClassify0 pFwpsPendClassify0 = NULL;
t_FwpsRedirectHandleCreate0 pFwpsRedirectHandleCreate0 = NULL;
t_FwpsAcquireClassifyHandle0 pFwpsAcquireClassifyHandle0 = NULL;

#pragma warning(disable:4152 4055)

static void 
wfplink_patchCode(void * pDest, ULONG len)
{
	KSPIN_LOCK lock;
    KLOCK_QUEUE_HANDLE lh;
	PMDL	mdl;
	void * pAddr;

	mdl = IoAllocateMdl(pDest, len, FALSE, FALSE, NULL);
	if (mdl)
	{
		MmBuildMdlForNonPagedPool(mdl);
		
		__try {
			MmProbeAndLockPages(mdl, KernelMode, IoWriteAccess);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			IoFreeMdl(mdl);
			return;
		}

		pAddr = MmMapLockedPages(mdl, KernelMode);
		if (pAddr)
		{
			sl_init(&lock);

			sl_lock(&lock, &lh);	
			__try {
				memset(pAddr, 0x90, len);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
			}
			sl_unlock(&lh);	

			MmUnmapLockedPages(pAddr, mdl);
		}

		MmUnlockPages(mdl);
		IoFreeMdl(mdl);
	}
}

static BOOLEAN wfplink_applyPatches()
{
	void * pModule;

	pModule = dynlink_getModuleBase("netio.sys");
	if (!pModule)
	{
		KdPrint((DPREFIX"dynlink_getModuleBase failed\n"));
		return FALSE;
	} 

	// Patch leaked callout contexts in NETIO.sys
	{
		char * pFunc;
		char inst_x64[] = { 0xf0, 0xff, 0x40, 0x04 };
		char inst_x86[] = { 0xf0, 0x0f, 0xc1, 0x0a };
		int i;
		
		pFunc = (char*)dynlink_getProcAddress(pModule, "FeAcquireWritableLayerDataPointer");
		if (pFunc)
		{
			for (i=0; i<512; i++)
			{
#if defined(_WIN64)
				if (memcmp(pFunc + i, inst_x64, sizeof(inst_x64)) == 0)
				{
					wfplink_patchCode(pFunc+i, sizeof(inst_x64));
					break;
				}
#else
				if (memcmp(pFunc + i, inst_x86, sizeof(inst_x86)) == 0)
				{
					wfplink_patchCode(pFunc+i, sizeof(inst_x86));
					break;
				}
#endif
			}
		}
	}

	return TRUE;
}

BOOLEAN 
wfplink_resolve()
{
	void * pModule;

	pModule = dynlink_getModuleBase("fwpkclnt.sys");
	if (!pModule)
	{
		KdPrint((DPREFIX"dynlink_getModuleBase failed\n"));
		return FALSE;
	} 

	pFwpmBfeStateGet0 = (t_FwpmBfeStateGet0)dynlink_getProcAddress(pModule, "FwpmBfeStateGet0");
	if (!pFwpmBfeStateGet0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmBfeStateGet0\n"));
		return FALSE;
	}

	pFwpmBfeStateSubscribeChanges0 = (t_FwpmBfeStateSubscribeChanges0)dynlink_getProcAddress(pModule, "FwpmBfeStateSubscribeChanges0");
	if (!pFwpmBfeStateSubscribeChanges0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmBfeStateSubscribeChanges0\n"));
		return FALSE;
	}

	pFwpmBfeStateUnsubscribeChanges0 = (t_FwpmBfeStateUnsubscribeChanges0)dynlink_getProcAddress(pModule, "FwpmBfeStateUnsubscribeChanges0");
	if (!pFwpmBfeStateUnsubscribeChanges0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmBfeStateUnsubscribeChanges0\n"));
		return FALSE;
	}

	pFwpsCalloutRegister1 = (t_FwpsCalloutRegister1)dynlink_getProcAddress(pModule, "FwpsCalloutRegister1");
	if (!pFwpsCalloutRegister1)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsCalloutRegister1\n"));
		return FALSE;
	}

	pFwpsCalloutUnregisterByKey0 = (t_FwpsCalloutUnregisterByKey0)dynlink_getProcAddress(pModule, "FwpsCalloutUnregisterByKey0");
	if (!pFwpsCalloutUnregisterByKey0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsCalloutUnregisterByKey0\n"));
		return FALSE;
	}

	pFwpmTransactionBegin0 = (t_FwpmTransactionBegin0)dynlink_getProcAddress(pModule, "FwpmTransactionBegin0");
	if (!pFwpmTransactionBegin0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmTransactionBegin0\n"));
		return FALSE;
	}

	pFwpmTransactionCommit0 = (t_FwpmTransactionCommit0)dynlink_getProcAddress(pModule, "FwpmTransactionCommit0");
	if (!pFwpmTransactionCommit0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmTransactionCommit0\n"));
		return FALSE;
	}

	pFwpmEngineClose0 = (t_FwpmEngineClose0)dynlink_getProcAddress(pModule, "FwpmEngineClose0");
	if (!pFwpmEngineClose0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for pFwpmEngineClose0\n"));
		return FALSE;
	}

	pFwpmCalloutAdd0 = (t_FwpmCalloutAdd0)dynlink_getProcAddress(pModule, "FwpmCalloutAdd0");
	if (!pFwpmCalloutAdd0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmCalloutAdd0\n"));
		return FALSE;
	}

	pFwpmFilterAdd0 = (t_FwpmFilterAdd0)dynlink_getProcAddress(pModule, "FwpmFilterAdd0");
	if (!pFwpmFilterAdd0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmFilterAdd0\n"));
		return FALSE;
	}

	pFwpmSubLayerCreateEnumHandle0 = (t_FwpmSubLayerCreateEnumHandle0)dynlink_getProcAddress(pModule, "FwpmSubLayerCreateEnumHandle0");
	if (!pFwpmSubLayerCreateEnumHandle0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmSubLayerCreateEnumHandle0\n"));
		return FALSE;
	}

	pFwpmSubLayerEnum0 = (t_FwpmSubLayerEnum0)dynlink_getProcAddress(pModule, "FwpmSubLayerEnum0");
	if (!pFwpmSubLayerEnum0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmSubLayerEnum0\n"));
		return FALSE;
	}

	pFwpmFreeMemory0 = (t_FwpmFreeMemory0)dynlink_getProcAddress(pModule, "FwpmFreeMemory0");
	if (!pFwpmFreeMemory0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmFreeMemory0\n"));
		return FALSE;
	}

	pFwpmSubLayerDestroyEnumHandle0 = (t_FwpmSubLayerDestroyEnumHandle0)dynlink_getProcAddress(pModule, "FwpmSubLayerDestroyEnumHandle0");
	if (!pFwpmSubLayerDestroyEnumHandle0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmSubLayerDestroyEnumHandle0\n"));
		return FALSE;
	}

	pFwpmSubLayerAdd0 = (t_FwpmSubLayerAdd0)dynlink_getProcAddress(pModule, "FwpmSubLayerAdd0");
	if (!pFwpmSubLayerAdd0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmSubLayerAdd0\n"));
		return FALSE;
	}

	pFwpmTransactionAbort0 = (t_FwpmTransactionAbort0)dynlink_getProcAddress(pModule, "FwpmTransactionAbort0");
	if (!pFwpmTransactionAbort0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmTransactionAbort0\n"));
		return FALSE;
	}

	pFwpmEngineOpen0 = (t_FwpmEngineOpen0)dynlink_getProcAddress(pModule, "FwpmEngineOpen0");
	if (!pFwpmEngineOpen0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmEngineOpen0\n"));
		return FALSE;
	}

	pFwpmProviderAdd0 = (t_FwpmProviderAdd0)dynlink_getProcAddress(pModule, "FwpmProviderAdd0");
	if (!pFwpmProviderAdd0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmProviderAdd0\n"));
		return FALSE;
	}

	pFwpmSubLayerDeleteByKey0 = (t_FwpmSubLayerDeleteByKey0)dynlink_getProcAddress(pModule, "FwpmSubLayerDeleteByKey0");
	if (!pFwpmSubLayerDeleteByKey0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmSubLayerDeleteByKey0\n"));
		return FALSE;
	}

	pFwpmProviderContextDeleteByKey0 = (t_FwpmProviderContextDeleteByKey0)dynlink_getProcAddress(pModule, "FwpmProviderContextDeleteByKey0");
	if (!pFwpmProviderContextDeleteByKey0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpmProviderContextDeleteByKey0\n"));
		return FALSE;
	}

	pFwpsInjectionHandleCreate0 = (t_FwpsInjectionHandleCreate0)dynlink_getProcAddress(pModule, "FwpsInjectionHandleCreate0");
	if (!pFwpsInjectionHandleCreate0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsInjectionHandleCreate0\n"));
		return FALSE;
	}

	pFwpsInjectionHandleDestroy0 = (t_FwpsInjectionHandleDestroy0)dynlink_getProcAddress(pModule, "FwpsInjectionHandleDestroy0");
	if (!pFwpsInjectionHandleDestroy0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsInjectionHandleDestroy0\n"));
		return FALSE;
	}

	pFwpsCopyStreamDataToBuffer0 = (t_FwpsCopyStreamDataToBuffer0)dynlink_getProcAddress(pModule, "FwpsCopyStreamDataToBuffer0");
	if (!pFwpsCopyStreamDataToBuffer0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsCopyStreamDataToBuffer0\n"));
		return FALSE;
	}

	pFwpsFreeCloneNetBufferList0 = (t_FwpsFreeCloneNetBufferList0)dynlink_getProcAddress(pModule, "FwpsFreeCloneNetBufferList0");
	if (!pFwpsFreeCloneNetBufferList0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsFreeCloneNetBufferList0\n"));
		return FALSE;
	}

	pFwpsStreamInjectAsync0 = (t_FwpsStreamInjectAsync0)dynlink_getProcAddress(pModule, "FwpsStreamInjectAsync0");
	if (!pFwpsStreamInjectAsync0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsStreamInjectAsync0\n"));
		return FALSE;
	}

	pFwpsAllocateNetBufferAndNetBufferList0 = (t_FwpsAllocateNetBufferAndNetBufferList0)dynlink_getProcAddress(pModule, "FwpsAllocateNetBufferAndNetBufferList0");
	if (!pFwpsAllocateNetBufferAndNetBufferList0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsAllocateNetBufferAndNetBufferList0\n"));
		return FALSE;
	}

	pFwpsFreeNetBufferList0 = (t_FwpsFreeNetBufferList0)dynlink_getProcAddress(pModule, "FwpsFreeNetBufferList0");
	if (!pFwpsFreeNetBufferList0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsFreeNetBufferList0\n"));
		return FALSE;
	}

	pFwpsConstructIpHeaderForTransportPacket0 = (t_FwpsConstructIpHeaderForTransportPacket0)dynlink_getProcAddress(pModule, "FwpsConstructIpHeaderForTransportPacket0");
	if (!pFwpsConstructIpHeaderForTransportPacket0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsConstructIpHeaderForTransportPacket0\n"));
		return FALSE;
	}

	pFwpsInjectNetworkSendAsync0 = (t_FwpsInjectNetworkSendAsync0)dynlink_getProcAddress(pModule, "FwpsInjectNetworkSendAsync0");
	if (!pFwpsInjectNetworkSendAsync0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsInjectNetworkSendAsync0\n"));
		return FALSE;
	}

	pFwpsInjectNetworkReceiveAsync0 = (t_FwpsInjectNetworkReceiveAsync0)dynlink_getProcAddress(pModule, "FwpsInjectNetworkReceiveAsync0");
	if (!pFwpsInjectNetworkReceiveAsync0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsInjectNetworkReceiveAsync0\n"));
		return FALSE;
	}

	pFwpsInjectTransportSendAsync0 = (t_FwpsInjectTransportSendAsync0)dynlink_getProcAddress(pModule, "FwpsInjectTransportSendAsync0");
	if (!pFwpsInjectTransportSendAsync0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsInjectTransportSendAsync0\n"));
		return FALSE;
	}

	pFwpsInjectTransportReceiveAsync0 = (t_FwpsInjectTransportReceiveAsync0)dynlink_getProcAddress(pModule, "FwpsInjectTransportReceiveAsync0");
	if (!pFwpsInjectTransportReceiveAsync0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsInjectTransportReceiveAsync0\n"));
		return FALSE;
	}

	pFwpsAcquireWritableLayerDataPointer0 = (t_FwpsAcquireWritableLayerDataPointer0)dynlink_getProcAddress(pModule, "FwpsAcquireWritableLayerDataPointer0");
	if (!pFwpsAcquireWritableLayerDataPointer0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsAcquireWritableLayerDataPointer0\n"));
		return FALSE;
	}

	pFwpsApplyModifiedLayerData0 = (t_FwpsApplyModifiedLayerData0)dynlink_getProcAddress(pModule, "FwpsApplyModifiedLayerData0");
	if (!pFwpsApplyModifiedLayerData0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsApplyModifiedLayerData0\n"));
		return FALSE;
	}

	pFwpsFlowAssociateContext0 = (t_FwpsFlowAssociateContext0)dynlink_getProcAddress(pModule, "FwpsFlowAssociateContext0");
	if (!pFwpsFlowAssociateContext0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsFlowAssociateContext0\n"));
		return FALSE;
	}

	pFwpsFlowRemoveContext0 = (t_FwpsFlowRemoveContext0)dynlink_getProcAddress(pModule, "FwpsFlowRemoveContext0");
	if (!pFwpsFlowRemoveContext0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsFlowRemoveContext0\n"));
		return FALSE;
	}

	pFwpsCloneStreamData0 = (t_FwpsCloneStreamData0)dynlink_getProcAddress(pModule, "FwpsCloneStreamData0");
	if (!pFwpsCloneStreamData0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsCloneStreamData0\n"));
		return FALSE;
	}

	pFwpsDiscardClonedStreamData0 = (t_FwpsDiscardClonedStreamData0)dynlink_getProcAddress(pModule, "FwpsDiscardClonedStreamData0");
	if (!pFwpsDiscardClonedStreamData0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsDiscardClonedStreamData0\n"));
		return FALSE;
	}

	pFwpsCompleteClassify0 = (t_FwpsCompleteClassify0)dynlink_getProcAddress(pModule, "FwpsCompleteClassify0");
	if (!pFwpsCompleteClassify0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsCompleteClassify0\n"));
		return FALSE;
	}

	pFwpsReleaseClassifyHandle0 = (t_FwpsReleaseClassifyHandle0)dynlink_getProcAddress(pModule, "FwpsReleaseClassifyHandle0");
	if (!pFwpsReleaseClassifyHandle0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsReleaseClassifyHandle0\n"));
		return FALSE;
	}

	pFwpsQueryPacketInjectionState0 = (t_FwpsQueryPacketInjectionState0)dynlink_getProcAddress(pModule, "FwpsQueryPacketInjectionState0");
	if (!pFwpsQueryPacketInjectionState0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsQueryPacketInjectionState0\n"));
		return FALSE;
	}

	pFwpsPendClassify0 = (t_FwpsPendClassify0)dynlink_getProcAddress(pModule, "FwpsPendClassify0");
	if (!pFwpsPendClassify0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsPendClassify0\n"));
		return FALSE;
	}

	pFwpsAcquireClassifyHandle0 = (t_FwpsAcquireClassifyHandle0)dynlink_getProcAddress(pModule, "FwpsAcquireClassifyHandle0");
	if (!pFwpsAcquireClassifyHandle0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsAcquireClassifyHandle0\n"));
		return FALSE;
	}

	pFwpsRedirectHandleCreate0 = (t_FwpsRedirectHandleCreate0)dynlink_getProcAddress(pModule, "FwpsRedirectHandleCreate0");
	if (!pFwpsRedirectHandleCreate0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsRedirectHandleCreate0\n"));
		g_windowsVersion = 7;
	} else
	{
		g_windowsVersion = 8;
	}

	pFwpsRedirectHandleDestroy0 = (t_FwpsRedirectHandleDestroy0)dynlink_getProcAddress(pModule, "FwpsRedirectHandleDestroy0");
	if (!pFwpsRedirectHandleDestroy0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsRedirectHandleDestroy0\n"));
		g_windowsVersion = 7;
	} else
	{
		g_windowsVersion = 8;
	}

	pFwpsFlowAbort0 = (t_FwpsFlowAbort0)dynlink_getProcAddress(pModule, "FwpsFlowAbort0");
	if (!pFwpsFlowAbort0)
	{
		KdPrint((DPREFIX"dynlink_getProcAddress failed for FwpsFlowAbort0\n"));
		g_windowsVersion = 7;
	} else
	{
		g_windowsVersion = 8;
	}

// Removed for compatibility with antiviruses	
//	wfplink_applyPatches();

	return TRUE;
}

BOOLEAN
wfplink_init() 
{
	if (!wfplink_resolve())
		return FALSE;

	return TRUE;
}

BOOLEAN
wfplink_checkMinimumWindowsVersion(int version)
{
	KdPrint((DPREFIX"wfplink_checkMinimumWindowsVersion version %d\n", g_windowsVersion));
	return (g_windowsVersion >= version)? TRUE : FALSE;
}
