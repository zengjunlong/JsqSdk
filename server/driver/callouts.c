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
#include "callouts.h"
#include "devctrl.h"
#include "srv_callouts.h"

#ifdef _WPPTRACE
#include "callouts.tmh"
#endif

#define NFSDK_STREAM_CALLOUT_DESCRIPTION L"NFSDK Srv Callout"
#define NFSDK_STREAM_CALLOUT_NAME L"NFSDK Srv Callout"

#define NFSDK_SUBLAYER_NAME L"NFSDK Srv Sublayer"

#define NFSDK_PROVIDER_NAME L"NFSDK Srv Provider"

enum CALLOUT_GUIDS
{
	CG_INBOUND_MAC_FRAME,
	CG_OUTBOUND_MAC_FRAME,
	CG_MAX
};

static GUID		g_calloutGuids[CG_MAX];
static UINT32	g_calloutIds[CG_MAX];
static HANDLE	g_engineHandle = NULL;
static GUID		g_providerGuid;
static GUID		g_sublayerGuid;

static BOOLEAN	g_initialized = FALSE;

void
callouts_unregisterCallouts()
{
	NTSTATUS status;
	int i;

	for (i=0; i<CG_MAX; i++)
	{
		status = FwpsCalloutUnregisterByKey(&g_calloutGuids[i]);
		if (!NT_SUCCESS(status))
		{
			ASSERT(0);
		}
	}
}

struct NF_CALLOUT
{
   FWPS_CALLOUT_CLASSIFY_FN classifyFunction;
   FWPS_CALLOUT_NOTIFY_FN notifyFunction;
   FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteFunction;
   GUID const* calloutKey;
   UINT32 flags;
   UINT32* calloutId;
} g_callouts[] = {
	{
		(FWPS_CALLOUT_CLASSIFY_FN)srvcallouts_MacFrameCallout,
        (FWPS_CALLOUT_NOTIFY_FN)srvcallouts_MacFrameNotify,
        NULL,
		&g_calloutGuids[CG_INBOUND_MAC_FRAME],
        0, // No flags
		&g_calloutIds[CG_INBOUND_MAC_FRAME]
	},
	{
		(FWPS_CALLOUT_CLASSIFY_FN)srvcallouts_MacFrameCallout,
        (FWPS_CALLOUT_NOTIFY_FN)srvcallouts_MacFrameNotify,
        NULL,
		&g_calloutGuids[CG_OUTBOUND_MAC_FRAME],
        0, // No flags
		&g_calloutIds[CG_OUTBOUND_MAC_FRAME]
	}
};

NTSTATUS
callouts_registerCallout(
   IN OUT void* deviceObject,
   IN  FWPS_CALLOUT_CLASSIFY_FN classifyFunction,
   IN  FWPS_CALLOUT_NOTIFY_FN notifyFunction,
   IN  FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteFunction,
   IN  GUID const* calloutKey,
   IN  UINT32 flags,
   OUT UINT32* calloutId
   )
{
    FWPS_CALLOUT sCallout;
    NTSTATUS status = STATUS_SUCCESS;

    memset(&sCallout, 0, sizeof(sCallout));

    sCallout.calloutKey = *calloutKey;
    sCallout.flags = flags;
    sCallout.classifyFn = classifyFunction;
    sCallout.notifyFn = notifyFunction;
    sCallout.flowDeleteFn = flowDeleteFunction;

    status = FwpsCalloutRegister(deviceObject, &sCallout, calloutId);

    return status;
}


NTSTATUS
callouts_registerCallouts(
   IN OUT void* deviceObject
   )
{
	NTSTATUS status = STATUS_SUCCESS;
	int i;

	status = FwpmTransactionBegin(g_engineHandle, 0);
	if (!NT_SUCCESS(status))
	{
		FwpmEngineClose(g_engineHandle);
        g_engineHandle = NULL;
		return status;
	}

	for(;;)
	{
		for (i=0; i<sizeof(g_callouts)/sizeof(g_callouts[0]); i++)
		{
			status = callouts_registerCallout(deviceObject,
				g_callouts[i].classifyFunction,
				g_callouts[i].notifyFunction,
				g_callouts[i].flowDeleteFunction,
				g_callouts[i].calloutKey,
				g_callouts[i].flags,
				g_callouts[i].calloutId);
			
			if (!NT_SUCCESS(status))
			{
				break;
			}
		}

		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = FwpmTransactionCommit(g_engineHandle);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		break;
	}

	if (!NT_SUCCESS(status))
	{
		FwpmTransactionAbort(g_engineHandle);
		FwpmEngineClose(g_engineHandle);
        g_engineHandle = NULL;
	}
	
	return status;
}


NTSTATUS
callouts_addFilter(const GUID * calloutKey, const GUID * layer, FWPM_SUBLAYER * subLayer)
{
	FWPM_CALLOUT callout;
	FWPM_DISPLAY_DATA displayData;
	FWPM_FILTER filter;
	NTSTATUS status;

	for (;;)
	{
		RtlZeroMemory(&callout, sizeof(FWPM_CALLOUT));
		displayData.description = NFSDK_STREAM_CALLOUT_DESCRIPTION;
		displayData.name = NFSDK_STREAM_CALLOUT_NAME;

		callout.calloutKey = *calloutKey;
		callout.displayData = displayData;
		callout.applicableLayer = *layer;
		callout.flags = 0; 

		status = FwpmCalloutAdd(g_engineHandle, &callout, NULL, NULL);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		RtlZeroMemory(&filter, sizeof(FWPM_FILTER));

		filter.layerKey = *layer;
		filter.displayData.name = NFSDK_STREAM_CALLOUT_NAME;
		filter.displayData.description = NFSDK_STREAM_CALLOUT_NAME;
		filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
		filter.action.calloutKey = *calloutKey;
		filter.filterCondition = NULL;
		filter.subLayerKey = subLayer->subLayerKey;
		filter.weight.type = FWP_EMPTY; // auto-weight.
		filter.numFilterConditions = 0;

		status = FwpmFilterAdd(g_engineHandle,
						   &filter,
						   NULL,
						   NULL);

		if (!NT_SUCCESS(status))
		{
			break;
		}
	
		break;
	} 

	return status;
}

NTSTATUS
callouts_addFilters()
{
	FWPM_SUBLAYER subLayer;
	NTSTATUS status;

	status = FwpmTransactionBegin(g_engineHandle, 0);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	
	for (;;)
	{
		RtlZeroMemory(&subLayer, sizeof(FWPM_SUBLAYER)); 

		subLayer.subLayerKey = g_sublayerGuid;
		subLayer.displayData.name = NFSDK_SUBLAYER_NAME;
		subLayer.displayData.description = NFSDK_SUBLAYER_NAME;
		subLayer.flags = 0;
		subLayer.weight = 0;

		status = FwpmSubLayerAdd(g_engineHandle, &subLayer, NULL);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = callouts_addFilter(
			&g_calloutGuids[CG_INBOUND_MAC_FRAME], 
			&FWPM_LAYER_INBOUND_MAC_FRAME_ETHERNET,
			&subLayer);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = callouts_addFilter(
			&g_calloutGuids[CG_OUTBOUND_MAC_FRAME], 
			&FWPM_LAYER_OUTBOUND_MAC_FRAME_ETHERNET,
			&subLayer);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		status = FwpmTransactionCommit(g_engineHandle);
		if (!NT_SUCCESS(status))
		{
			break;
		}

		break;
	} 
	
	if (!NT_SUCCESS(status))
	{
		FwpmTransactionAbort(g_engineHandle);
	}

	return status;
}


NTSTATUS callouts_init(PDEVICE_OBJECT deviceObject)
{
	NTSTATUS status;
	DWORD dwStatus;
	FWPM_SESSION session = {0};
	int i;

	if (g_initialized)
		return STATUS_SUCCESS;

	ExUuidCreate(&g_providerGuid);
	ExUuidCreate(&g_sublayerGuid);
	
	for (i=0; i<CG_MAX; i++)
	{
		ExUuidCreate(&g_calloutGuids[i]);
	}

	session.flags = FWPM_SESSION_FLAG_DYNAMIC;

	status = FwpmEngineOpen(
                NULL,
                RPC_C_AUTHN_WINNT,
                NULL,
                &session,
                &g_engineHandle
                );
	if (!NT_SUCCESS(status))
	{
		KdPrint((DPREFIX"FwpmEngineOpen failed, status=%x\n", status));
		return status;
	}

	for (;;)
	{
		FWPM_PROVIDER provider;

		RtlZeroMemory(&provider, sizeof(provider));
		provider.displayData.description = NFSDK_PROVIDER_NAME;
		provider.displayData.name = NFSDK_PROVIDER_NAME;
		provider.providerKey = g_providerGuid;

		dwStatus = FwpmProviderAdd(g_engineHandle, &provider, NULL);
		if (dwStatus != 0)
		{
			KdPrint((DPREFIX"FwpmProviderAdd failed, status=%x\n", dwStatus));
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		status = callouts_registerCallouts(deviceObject);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DPREFIX"callouts_registerCallouts failed, status=%x\n", status));
			break;
		}

		status = callouts_addFilters();
		if (!NT_SUCCESS(status))
		{
			KdPrint((DPREFIX"callouts_addFilters failed, status=%x\n", status));
			break;
		}
	
		break;
	} 

	g_initialized = TRUE;

	if (!NT_SUCCESS(status))
	{
		callouts_free();
	}

	return status;
}

void callouts_free()
{
	KdPrint((DPREFIX"callouts_free\n"));

	if (!g_initialized)
		return;

	g_initialized = FALSE;

	callouts_unregisterCallouts();

	FwpmProviderContextDeleteByKey(g_engineHandle, &g_providerGuid);

	if (g_engineHandle)
	{
		FwpmEngineClose(g_engineHandle);
		g_engineHandle = NULL;
	}
}

