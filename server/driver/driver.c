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
#include "devctrl.h"
#include "flowctl.h"
#include "callouts.h"
#include "srv_callouts.h"
#include "srv_rules.h"
#include "srv_ipfrag.h"
#include "interfaces.h"
#include "udp_port_pool.h"

#ifdef _WPPTRACE
#include "driver.tmh"
#endif

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD driverUnload;

static HANDLE g_bfeStateSubscribeHandle = NULL;

void cleanup()
{
	devctrl_setShutdown();

	flowctl_free();
	callouts_free();
	srvcallouts_free();
	srvrules_free();
	devctrl_free();
	interfaces_free();
	ipfrag_free();
	udp_port_pool_free();
}

VOID
driverUnload(
   IN  PDRIVER_OBJECT driverObject
   )
{
	UNREFERENCED_PARAMETER(driverObject);

	KdPrint((DPREFIX"driverUnload\n"));

	if (g_bfeStateSubscribeHandle)
	{
		FwpmBfeStateUnsubscribeChanges(g_bfeStateSubscribeHandle);
		g_bfeStateSubscribeHandle = NULL;
	}

	cleanup();

#ifdef _WPPTRACE
	WPP_CLEANUP(driverObject);
#endif
}

VOID NTAPI
bfeStateCallback(
    IN OUT void  *context,
    IN FWPM_SERVICE_STATE  newState
    )
{
	UNREFERENCED_PARAMETER(context);

	if (newState == FWPM_SERVICE_RUNNING)
	{
		NTSTATUS status = callouts_init(devctrl_getDeviceObject());
		if (!NT_SUCCESS(status))
		{
			KdPrint((DPREFIX"bfeStateCallback callouts_init failed, status=%x\n", status));
		}
	}
}

NTSTATUS
DriverEntry(
   IN  PDRIVER_OBJECT  driverObject,
   IN  PUNICODE_STRING registryPath
   )
{
	int i;
	NTSTATUS status;

#ifdef _NXPOOLS
#ifdef USE_NTDDI
#if (NTDDI_VERSION >= NTDDI_WIN8)
	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);
#endif
#endif
#endif

	for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		driverObject->MajorFunction[i] = (PDRIVER_DISPATCH)devctrl_dispatch;
	}

    driverObject->DriverUnload = driverUnload;

	for (;;)
	{
		status = devctrl_init(driverObject, registryPath);
		if (!NT_SUCCESS(status))
		{
			KdPrint((DPREFIX"devctrl_init failed, status=%x\n", status));
			break;
		}

#ifdef _WPPTRACE
	   	WPP_SYSTEMCONTROL(driverObject);
		WPP_INIT_TRACING(devctrl_getDeviceObject(), registryPath);
#endif

		if (!flowctl_init())
		{
			KdPrint((DPREFIX"flowctl_init failed\n"));
			break;
		}

		status = srvrules_init();
		if (!NT_SUCCESS(status))
		{
			KdPrint((DPREFIX"srvrules_init failed, status=%x\n", status));
			break;
		}

		status = srvcallouts_init();
		if (!NT_SUCCESS(status))
		{
			KdPrint((DPREFIX"srvcallouts_init failed, status=%x\n", status));
			break;
		}

		if (!interfaces_init())
		{
			KdPrint((DPREFIX"interfaces_init failed\n"));
			break;
		}

		if (!ipfrag_init())
		{
			KdPrint((DPREFIX"ipfrag_init failed\n"));
			break;
		}

		if (!udp_port_pool_init())
		{
			KdPrint((DPREFIX"udp_port_pool_init failed\n"));
			break;
		}

		if (FwpmBfeStateGet() == FWPM_SERVICE_RUNNING)
		{
			status = callouts_init(devctrl_getDeviceObject());
			if (!NT_SUCCESS(status))
			{
				KdPrint((DPREFIX"callouts_init failed, status=%x\n", status));
				break;
			}
		} else
		{
			status = FwpmBfeStateSubscribeChanges(
				devctrl_getDeviceObject(),
				bfeStateCallback,
				NULL,
				&g_bfeStateSubscribeHandle);
			if (!NT_SUCCESS(status))
			{
				KdPrint((DPREFIX"FwpmBfeStateSubscribeChanges failed, status=%x\n", status));
				break;
			}
		}

		break;
	}

	if (!NT_SUCCESS(status))
	{
		cleanup();
	}

	return status;
}


