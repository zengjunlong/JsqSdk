//
// 	NetFilterSDK 
// 	Copyright (C) Vitaly Sidorov
//	All rights reserved.
//
//	This file is a part of the NetFilter SDK.
//	The code and information is provided "as-is" without
//	warranty of any kind, either expressed or implied.
//


#ifndef _DEVCTRL_H
#define _DEVCTRL_H

#include "nfsrvext.h"
#include "hashtable.h"

NTSTATUS devctrl_init(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
void	 devctrl_free();
DRIVER_DISPATCH devctrl_dispatch;
NTSTATUS devctrl_dispatch(IN PDEVICE_OBJECT DeviceObject, IN PIRP irp);
BOOLEAN	 devctrl_isProxyAttached();
ULONG	 devctrl_getProxyPid();
PDEVICE_OBJECT devctrl_getDeviceObject();
void	devctrl_setShutdown();
BOOLEAN	devctrl_isShutdown();

#endif