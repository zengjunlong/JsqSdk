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
#include "callouts.h"
#include "flowctl.h"
#include "srv_callouts.h"
#include "srv_rules.h"
#include "interfaces.h"
#include "udp_port_pool.h"

#ifdef _WPPTRACE
#include "devctrl.tmh"
#endif

#define NF_CTRL_DEVICE			L"\\Device\\CtrlNFSRV"
#define NF_CTRL_DEVICE_LINK		L"\\DosDevices\\CtrlNFSRV"

static UNICODE_STRING g_ctrlDeviceName;
static wchar_t g_wszCtrlDeviceName[MAX_PATH];

static UNICODE_STRING g_ctrlDeviceLinkName;
static wchar_t g_wszCtrlDeviceLinkName[MAX_PATH];

/**
 *  Our device for comminicating with user-mode
 */
static PDEVICE_OBJECT g_deviceControl;

/**
 *	TRUE, if some process attached to driver API
 */
static BOOLEAN		g_proxyAttached = FALSE;

/**
 *	pid of the attached process
 */
static HANDLE		g_proxyPid;

static BOOLEAN	  g_initialized = FALSE;

static BOOLEAN g_shutdown = FALSE;

void devctrl_serviceReads();

DRIVER_CANCEL devctrl_cancelRead;

PDEVICE_OBJECT devctrl_getDeviceObject()
{
	return g_deviceControl;
}

BOOLEAN devctrl_isProxyAttached()
{
	BOOLEAN		res;

	res = g_proxyAttached;

	return res;
}

ULONG devctrl_getProxyPid()
{
	return *(ULONG*)&g_proxyPid;
}

BOOLEAN	devctrl_isShutdown()
{
	BOOLEAN		res;

	res = g_shutdown;
	
	return res;
}

void devctrl_setShutdown()
{
	g_shutdown = TRUE;
}

NTSTATUS devctrl_init(PDRIVER_OBJECT driverObject, PUNICODE_STRING registryPath)
{
	NTSTATUS 	status;
	wchar_t wszDriverName[MAX_PATH] = { L'\0' };
	int i, driverNameLen = 0;

	g_deviceControl = NULL;
	g_proxyAttached = FALSE;
	g_initialized = FALSE;

	for (;;)
	{
		// Get driver name from registry path
		for (i = registryPath->Length / sizeof(wchar_t) - 1; i >= 0; i--)
		{
			if (registryPath->Buffer[i] == L'\\' ||
				registryPath->Buffer[i] == L'/')
			{
				i++;

				while (registryPath->Buffer[i] && 
					(registryPath->Buffer[i] != L'.') &&
					(driverNameLen < MAX_PATH))
				{
					wszDriverName[driverNameLen] = registryPath->Buffer[i];
					i++;
					driverNameLen++;
				}

				wszDriverName[driverNameLen] = L'\0';

				break;
			}
		}

		if (driverNameLen == 0)
		{
			status = STATUS_UNSUCCESSFUL;
			break;
		}

		// Initialize the control device name
		*g_wszCtrlDeviceName = L'\0';
		g_ctrlDeviceName.Buffer = g_wszCtrlDeviceName;
		g_ctrlDeviceName.Length = 0;
		g_ctrlDeviceName.MaximumLength = sizeof(g_wszCtrlDeviceName);
		RtlAppendUnicodeToString(&g_ctrlDeviceName, NF_CTRL_DEVICE);
		RtlAppendUnicodeToString(&g_ctrlDeviceName, wszDriverName);

		// Initialize the control link device name
		*g_wszCtrlDeviceLinkName = L'\0';
		g_ctrlDeviceLinkName.Buffer = g_wszCtrlDeviceLinkName;
		g_ctrlDeviceLinkName.Length = 0;
		g_ctrlDeviceLinkName.MaximumLength = sizeof(g_wszCtrlDeviceLinkName);
		RtlAppendUnicodeToString(&g_ctrlDeviceLinkName, NF_CTRL_DEVICE_LINK);
		RtlAppendUnicodeToString(&g_ctrlDeviceLinkName, wszDriverName);

		status = IoCreateDevice(
					driverObject,
					0,
					&g_ctrlDeviceName,
        			FILE_DEVICE_UNKNOWN,
        			FILE_DEVICE_SECURE_OPEN,
        			FALSE,
        			&g_deviceControl);

		if (!NT_SUCCESS(status))
		{
			break;
		}

		g_deviceControl->Flags &= ~DO_DEVICE_INITIALIZING;

		status = IoCreateSymbolicLink(&g_ctrlDeviceLinkName, &g_ctrlDeviceName);
		if (!NT_SUCCESS(status))
		{
			IoDeleteDevice(g_deviceControl);
			g_deviceControl = NULL;
			break;
		}

		g_deviceControl->Flags &= ~DO_DEVICE_INITIALIZING;
		g_deviceControl->Flags |= DO_DIRECT_IO;

		break;
	}

	g_initialized = TRUE;

	if (!NT_SUCCESS(status))
	{
		devctrl_free();
		return status;
	}

	return status;
}

void devctrl_free()
{
	KdPrint((DPREFIX"devctrl_free\n"));

	if (!g_initialized)
		return;

	if (g_deviceControl != NULL)
	{
		IoDeleteSymbolicLink(&g_ctrlDeviceLinkName);
		IoDeleteDevice(g_deviceControl);
		g_deviceControl = NULL;
	}

	g_initialized = FALSE;
}

NTSTATUS devctrl_create(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS 	status;
	HANDLE		pid = PsGetCurrentProcessId();

	UNREFERENCED_PARAMETER(irpSp);

	if (g_proxyAttached)
	{
		status = STATUS_INVALID_DEVICE_REQUEST;
	} else
	{
		g_proxyPid = pid;
		g_proxyAttached = TRUE;
		status = STATUS_SUCCESS;
	}

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS devctrl_close(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	UNREFERENCED_PARAMETER(irpSp);

	KdPrint((DPREFIX"devctrl_close\n"));

	flowctl_delete(0);

	g_proxyPid = 0;
	g_proxyAttached = FALSE;

	srvrules_remove_all();
	srvcallouts_cleanup();

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS devctrl_addFlowCtl(PIRP irp, PIO_STACK_LOCATION irpSp)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (ioBuffer && (outputBufferLength >= sizeof(ULONG)) && (inputBufferLength >= sizeof(NF_SRV_FLOWCTL_DATA)))
	{
		PNF_SRV_FLOWCTL_DATA pFlowData = (PNF_SRV_FLOWCTL_DATA)ioBuffer;

		*(ULONG*)ioBuffer = flowctl_add(pFlowData->inLimit, pFlowData->outLimit);
		irp->IoStatus.Information = sizeof(ULONG);
	} else
	{
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
		
	return STATUS_SUCCESS;
}

NTSTATUS devctrl_deleteFlowCtl(PIRP irp, PIO_STACK_LOCATION irpSp)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	NTSTATUS status;

	if (ioBuffer && (inputBufferLength >= sizeof(ULONG)))
	{
		ULONG fcHandle = *(ULONG*)ioBuffer;

		if (flowctl_delete(fcHandle))
		{
			status = STATUS_SUCCESS;
		} else
		{
			status = STATUS_INVALID_PARAMETER;
		}
	} else
	{
		status = STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS devctrl_modifyFlowCtl(PIRP irp, PIO_STACK_LOCATION irpSp)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	NTSTATUS status;

	if (ioBuffer && (inputBufferLength >= sizeof(NF_SRV_FLOWCTL_MODIFY_DATA)))
	{
		PNF_SRV_FLOWCTL_MODIFY_DATA pFlowData = (PNF_SRV_FLOWCTL_MODIFY_DATA)ioBuffer;

		if (flowctl_modifyLimits(pFlowData->fcHandle, pFlowData->data.inLimit, pFlowData->data.outLimit))
		{
			status = STATUS_SUCCESS;
		} else
		{
			status = STATUS_INVALID_PARAMETER;
		}
	} else
	{
		status = STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
		
	return status;
}

NTSTATUS devctrl_getFlowCtlStat(PIRP irp, PIO_STACK_LOCATION irpSp)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	NTSTATUS status;

	if (ioBuffer && (outputBufferLength >= sizeof(NF_SRV_FLOWCTL_STAT)) && (inputBufferLength >= sizeof(ULONG)))
	{
		ULONG fcHandle = *(ULONG*)ioBuffer;

		if (flowctl_getStat(fcHandle, (PNF_SRV_FLOWCTL_STAT)ioBuffer))
		{
			irp->IoStatus.Information = sizeof(NF_SRV_FLOWCTL_STAT);
			status = STATUS_SUCCESS;
		} else
		{
			irp->IoStatus.Information = 0;
			status = STATUS_INVALID_PARAMETER;
		}
	} else
	{
		irp->IoStatus.Information = 0;
		status = STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
		
	return status;
}

NTSTATUS devctrl_interfacesAdd(PIRP irp, PIO_STACK_LOCATION irpSp)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (ioBuffer && (inputBufferLength >= sizeof(NF_SRV_INTERFACE_IP)))
	{
		PNF_SRV_INTERFACE_IP pItf = (PNF_SRV_INTERFACE_IP)ioBuffer;

		interfaces_add(pItf->interfaceLuid, &pItf->address);
		irp->IoStatus.Information = 0;
	} else
	{
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
		
	return STATUS_SUCCESS;
}

NTSTATUS devctrl_interfacesClear(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	interfaces_clear();

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS devctrl_ruleAdd(PIRP irp, PIO_STACK_LOCATION irpSp, BOOLEAN toHead)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (ioBuffer && (inputBufferLength >= sizeof(NF_SRV_RULE)))
	{
		PNF_SRV_RULE pItf = (PNF_SRV_RULE)ioBuffer;

		srvrules_add((PNF_SRV_RULE)ioBuffer, toHead);
		irp->IoStatus.Information = 0;
	} else
	{
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
		
	return STATUS_SUCCESS;
}

NTSTATUS devctrl_ruleClear(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	srvrules_remove_all();

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS devctrl_getDestinationAddress(PIRP irp, PIO_STACK_LOCATION irpSp, char protocol)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	NTSTATUS status;

	if (protocol == IPPROTO_UDP)
	{
		if (ioBuffer && (outputBufferLength >= sizeof(NF_ADDRESS)) && (inputBufferLength >= sizeof(NF_SRV_UDP_ADDRESSES)))
		{
			NF_SRV_UDP_ADDRESSES addresses = *(NF_SRV_UDP_ADDRESSES*)ioBuffer;

			if (srvcallouts_getDestinationAddress(protocol, &addresses.srcAddress, &addresses.dstAddress))
			{
				*(NF_ADDRESS*)ioBuffer = addresses.dstAddress;
				irp->IoStatus.Information = sizeof(NF_ADDRESS);
				status = STATUS_SUCCESS;
			} else
			{
				irp->IoStatus.Information = 0;
				status = STATUS_INVALID_PARAMETER;
			}
		} else
		{
			irp->IoStatus.Information = 0;
			status = STATUS_INVALID_PARAMETER;
		}
	} else
	{
		if (ioBuffer && (outputBufferLength >= sizeof(NF_ADDRESS)) && (inputBufferLength >= sizeof(NF_ADDRESS)))
		{
			NF_ADDRESS srcAddress = *(NF_ADDRESS*)ioBuffer;

			if (srvcallouts_getDestinationAddress(protocol, &srcAddress, (PNF_ADDRESS)ioBuffer))
			{
				irp->IoStatus.Information = sizeof(NF_ADDRESS);
				status = STATUS_SUCCESS;
			} else
			{
				irp->IoStatus.Information = 0;
				status = STATUS_INVALID_PARAMETER;
			}
		} else
		{
			irp->IoStatus.Information = 0;
			status = STATUS_INVALID_PARAMETER;
		}
	}

	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
		
	return status;
}

NTSTATUS devctrl_updateUDPDestinationAddress(PIRP irp, PIO_STACK_LOCATION irpSp)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	NTSTATUS status;

	if (ioBuffer && (inputBufferLength >= sizeof(NF_SRV_UDP_ADDRESSES_UPDATE)))
	{
		NF_SRV_UDP_ADDRESSES_UPDATE addresses = *(NF_SRV_UDP_ADDRESSES_UPDATE*)ioBuffer;

		if (srvcallouts_updateUDPDestinationAddress(&addresses.srcAddress, &addresses.dstAddress, &addresses.newDstAddress))
		{
			status = STATUS_SUCCESS;
		} else
		{
			status = STATUS_INVALID_PARAMETER;
		}
	} else
	{
		status = STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
		
	return status;
}

NTSTATUS devctrl_addUdpPort(PIRP irp, PIO_STACK_LOCATION irpSp, int ipFamily)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	NTSTATUS status;

	if (ioBuffer && (inputBufferLength >= sizeof(unsigned short)))
	{
		unsigned short port = *(unsigned short*)ioBuffer;

		if (udp_port_pool_add(ipFamily, port))
		{
			status = STATUS_SUCCESS;
		} else
		{
			status = STATUS_INVALID_PARAMETER;
		}
	} else
	{
		status = STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Information = 0;
	irp->IoStatus.Status = status;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
		
	return status;
}

NTSTATUS devctrl_clearUdpPorts(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	udp_port_pool_clear();

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS devctrl_setTimeout(PIRP irp, PIO_STACK_LOCATION irpSp)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;

	if (ioBuffer && (inputBufferLength >= sizeof(NF_SRV_TIMEOUT)))
	{
		PNF_SRV_TIMEOUT pt = (PNF_SRV_TIMEOUT)ioBuffer;

		srvcallouts_setTimeout(pt);
		irp->IoStatus.Information = 0;
	} else
	{
		irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
		
	return STATUS_SUCCESS;
}

NTSTATUS devctrl_clearTempRules(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;

	srvrules_remove_all_temp();

	status = STATUS_SUCCESS;

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS devctrl_addTempRule(PIRP irp, PIO_STACK_LOCATION irpSp)
{
    PVOID	ioBuffer = irp->AssociatedIrp.SystemBuffer;
    ULONG	inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
	NTSTATUS status;

	if (ioBuffer && (inputBufferLength >= sizeof(NF_SRV_RULE)))
	{
		PNF_SRV_RULE pRule = (PNF_SRV_RULE)ioBuffer;
		
		if (srvrules_add_temp(pRule))
		{
			status = STATUS_SUCCESS;
		} else
		{
			status = STATUS_NO_MEMORY;
		}
	} else
	{
		status = STATUS_INVALID_PARAMETER;
	}

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS devctrl_setTempRules(PIRP irp, PIO_STACK_LOCATION irpSp)
{
	NTSTATUS status;

	srvrules_set_temp();

	status = STATUS_SUCCESS;

	irp->IoStatus.Status = status;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS devctrl_dispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp)
{
	PIO_STACK_LOCATION irpSp;
	
	UNREFERENCED_PARAMETER(DeviceObject);

	irpSp = IoGetCurrentIrpStackLocation(irp);
	ASSERT(irpSp);
	
	KdPrint((DPREFIX"devctrl_dispatch mj=%d\n", irpSp->MajorFunction));

	switch (irpSp->MajorFunction) 
	{
	case IRP_MJ_CREATE:
		return devctrl_create(irp, irpSp);

	case IRP_MJ_READ:
	case IRP_MJ_WRITE:
		break;

	case IRP_MJ_CLOSE:
		return devctrl_close(irp, irpSp);

	case IRP_MJ_DEVICE_CONTROL:
		switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
		{
		case NF_SRV_ADD_FLOW_CTL:
			return devctrl_addFlowCtl(irp, irpSp);

		case NF_SRV_DELETE_FLOW_CTL:
			return devctrl_deleteFlowCtl(irp, irpSp);

		case NF_SRV_MODIFY_FLOW_CTL:
			return devctrl_modifyFlowCtl(irp, irpSp);

		case NF_SRV_GET_FLOW_CTL_STAT:
			return devctrl_getFlowCtlStat(irp, irpSp);

		case NF_SRV_INTERFACE_ADD:
			return devctrl_interfacesAdd(irp, irpSp);

		case NF_SRV_INTERFACE_CLEAR:
			return devctrl_interfacesClear(irp, irpSp);

		case NF_SRV_RULE_ADD_TO_HEAD:
			return devctrl_ruleAdd(irp, irpSp, TRUE);

		case NF_SRV_RULE_ADD_TO_TAIL:
			return devctrl_ruleAdd(irp, irpSp, FALSE);

		case NF_SRV_RULE_CLEAR:
			return devctrl_ruleClear(irp, irpSp);

		case NF_SRV_CLEAR_TEMP_RULES:
			return devctrl_clearTempRules(irp, irpSp);

		case NF_SRV_ADD_TEMP_RULE:
			return devctrl_addTempRule(irp, irpSp);

		case NF_SRV_SET_TEMP_RULES:
			return devctrl_setTempRules(irp, irpSp);

		case NF_SRV_GET_TCP_DST_ADDRESS:
			return devctrl_getDestinationAddress(irp, irpSp, IPPROTO_TCP);

		case NF_SRV_GET_UDP_DST_ADDRESS:
			return devctrl_getDestinationAddress(irp, irpSp, IPPROTO_UDP);

		case NF_SRV_SET_TIMEOUT:
			return devctrl_setTimeout(irp, irpSp);

		case NF_SRV_UPDATE_UDP_DST_ADDRESS:
			return devctrl_updateUDPDestinationAddress(irp, irpSp);

		case NF_SRV_ADD_UDP_PORT_IPv4:
			return devctrl_addUdpPort(irp, irpSp, AF_INET);

		case NF_SRV_ADD_UDP_PORT_IPv6:
			return devctrl_addUdpPort(irp, irpSp, AF_INET6);

		case NF_SRV_CLEAR_UDP_PORTS:
			return devctrl_clearUdpPorts(irp, irpSp);
		}
	}	

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
